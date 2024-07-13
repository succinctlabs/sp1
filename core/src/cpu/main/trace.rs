use std::borrow::BorrowMut;

use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::{PrimeField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{
    IntoParallelRefMutIterator, ParallelBridge, ParallelIterator, ParallelSlice,
};
use tracing::instrument;

use crate::{
    air::MachineAir,
    bytes::{event::ByteRecord, ByteLookupEvent, ByteOpcode},
    cpu::{
        main::trace::ByteOpcode::{U16Range, U8Range},
        CpuEvent,
    },
    memory::MemoryCols,
    runtime::{ExecutionRecord, MemoryRecordEnum, Opcode, Program, SyscallCode},
    stark::CpuChip,
};

use super::columns::{CpuCols, CPU_COL_MAP, NUM_CPU_COLS};

impl<F: PrimeField32> MachineAir<F> for CpuChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "CPU".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut values = vec![F::zero(); input.cpu_events.len() * NUM_CPU_COLS];

        let chunk_size = std::cmp::max(input.cpu_events.len() / num_cpus::get(), 1);
        values
            .chunks_mut(chunk_size * NUM_CPU_COLS)
            .enumerate()
            .par_bridge()
            .for_each(|(i, rows)| {
                rows.chunks_mut(NUM_CPU_COLS)
                    .enumerate()
                    .for_each(|(j, row)| {
                        let idx = i * chunk_size + j;
                        let cols: &mut CpuCols<F> = row.borrow_mut();
                        let mut byte_lookup_events = Vec::new();
                        self.event_to_row(
                            &input.cpu_events[idx],
                            &input.nonce_lookup,
                            cols,
                            &mut byte_lookup_events,
                        );
                    });
            });

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(values, NUM_CPU_COLS);

        // Pad the trace to a power of two.
        Self::pad_to_power_of_two::<F>(&mut trace.values);

        trace
    }

    #[instrument(name = "generate cpu dependencies", level = "debug", skip_all)]
    fn generate_dependencies(&self, input: &ExecutionRecord, output: &mut ExecutionRecord) {
        // Generate the trace rows for each event.
        let chunk_size = std::cmp::max(input.cpu_events.len() / num_cpus::get(), 1);

        let blu_events = input
            .cpu_events
            .par_chunks(chunk_size)
            .map(|ops: &[CpuEvent]| {
                // The blu map stores shard -> map(byte lookup event -> multiplicity).
                let mut blu: HashMap<u32, HashMap<ByteLookupEvent, usize>> = HashMap::new();
                ops.iter().for_each(|op| {
                    let mut row = [F::zero(); NUM_CPU_COLS];
                    let cols: &mut CpuCols<F> = row.as_mut_slice().borrow_mut();
                    self.event_to_row::<F>(op, &HashMap::new(), cols, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_sharded_byte_lookup_events(blu_events.iter().collect_vec());
    }

    fn included(&self, input: &Self::Record) -> bool {
        !input.cpu_events.is_empty()
    }
}

impl CpuChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &CpuEvent,
        nonce_lookup: &HashMap<usize, u32>,
        cols: &mut CpuCols<F>,
        blu_events: &mut impl ByteRecord,
    ) {
        // Populate shard and clk columns.
        self.populate_shard_clk(cols, event, blu_events);

        // Populate the nonce.
        cols.nonce = F::from_canonical_u32(
            nonce_lookup
                .get(&event.alu_lookup_id)
                .copied()
                .unwrap_or_default(),
        );

        // Populate basic fields.
        cols.pc = F::from_canonical_u32(event.pc);
        cols.next_pc = F::from_canonical_u32(event.next_pc);
        cols.instruction.populate(event.instruction);
        cols.selectors.populate(event.instruction);
        *cols.op_a_access.value_mut() = event.a.into();
        *cols.op_b_access.value_mut() = event.b.into();
        *cols.op_c_access.value_mut() = event.c.into();

        // Populate memory accesses for a, b, and c.
        if let Some(record) = event.a_record {
            cols.op_a_access.populate(event.channel, record, blu_events);
        }
        if let Some(MemoryRecordEnum::Read(record)) = event.b_record {
            cols.op_b_access.populate(event.channel, record, blu_events);
        }
        if let Some(MemoryRecordEnum::Read(record)) = event.c_record {
            cols.op_c_access.populate(event.channel, record, blu_events);
        }

        // Populate range checks for a.
        let a_bytes = cols
            .op_a_access
            .access
            .value
            .0
            .iter()
            .map(|x| x.as_canonical_u32())
            .collect::<Vec<_>>();
        blu_events.add_byte_lookup_event(ByteLookupEvent {
            shard: event.shard,
            channel: event.channel,
            opcode: ByteOpcode::U8Range,
            a1: 0,
            a2: 0,
            b: a_bytes[0],
            c: a_bytes[1],
        });
        blu_events.add_byte_lookup_event(ByteLookupEvent {
            shard: event.shard,
            channel: event.channel,
            opcode: ByteOpcode::U8Range,
            a1: 0,
            a2: 0,
            b: a_bytes[2],
            c: a_bytes[3],
        });

        cols.is_halt = F::from_bool(
            event.instruction.opcode == Opcode::ECALL
                && (cols.op_a_access.prev_value[0]
                    == F::from_canonical_u32(SyscallCode::HALT.syscall_id())),
        );

        // Assert that the instruction is not a no-op.
        cols.is_real = F::one();
    }

    /// Populates the shard, channel, and clk related rows.
    fn populate_shard_clk<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        blu_events: &mut impl ByteRecord,
    ) {
        cols.shard = F::from_canonical_u32(event.shard);
        cols.channel = F::from_canonical_u32(event.channel);
        cols.clk = F::from_canonical_u32(event.clk);

        let clk_16bit_limb = event.clk & 0xffff;
        let clk_8bit_limb = (event.clk >> 16) & 0xff;
        cols.clk_16bit_limb = F::from_canonical_u32(clk_16bit_limb);
        cols.clk_8bit_limb = F::from_canonical_u32(clk_8bit_limb);

        cols.channel_selectors.populate(event.channel);

        blu_events.add_byte_lookup_event(ByteLookupEvent::new(
            event.shard,
            event.channel,
            U16Range,
            event.shard,
            0,
            0,
            0,
        ));
        blu_events.add_byte_lookup_event(ByteLookupEvent::new(
            event.shard,
            event.channel,
            U16Range,
            clk_16bit_limb,
            0,
            0,
            0,
        ));
        blu_events.add_byte_lookup_event(ByteLookupEvent::new(
            event.shard,
            event.channel,
            U8Range,
            0,
            0,
            0,
            clk_8bit_limb,
        ));
    }

    fn pad_to_power_of_two<F: PrimeField>(values: &mut Vec<F>) {
        let n_real_rows = values.len() / NUM_CPU_COLS;
        let padded_nb_rows = if n_real_rows < 16 {
            16
        } else {
            n_real_rows.next_power_of_two()
        };
        values.resize(padded_nb_rows * NUM_CPU_COLS, F::zero());

        // Interpret values as a slice of arrays of length `NUM_CPU_COLS`
        let rows = unsafe {
            core::slice::from_raw_parts_mut(
                values.as_mut_ptr() as *mut [F; NUM_CPU_COLS],
                values.len() / NUM_CPU_COLS,
            )
        };

        rows[n_real_rows..].par_iter_mut().for_each(|padded_row| {
            padded_row[CPU_COL_MAP.selectors.imm_b] = F::one();
            padded_row[CPU_COL_MAP.selectors.imm_c] = F::one();
        });
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;

    use std::time::Instant;

    use super::*;

    use crate::runtime::tests::ssz_withdrawals_program;
    use crate::runtime::{tests::simple_program, Runtime};
    use crate::stark::DefaultProver;
    use crate::utils::{run_test, setup_logger, SP1CoreOpts};

    // #[test]
    // fn generate_trace() {
    //     let mut shard = ExecutionRecord::default();
    //     shard.cpu_events = vec![CpuEvent {
    //         shard: 1,
    //         channel: 0,
    //         clk: 6,
    //         pc: 1,
    //         next_pc: 5,
    //         instruction: Instruction {
    //             opcode: Opcode::ADD,
    //             op_a: 0,
    //             op_b: 1,
    //             op_c: 2,
    //             imm_b: false,
    //             imm_c: false,
    //         },
    //         a: 1,
    //         a_record: None,
    //         b: 2,
    //         b_record: None,
    //         c: 3,
    //         c_record: None,
    //         memory: None,
    //         memory_record: None,
    //         exit_code: 0,
    //     }];
    //     let chip = CpuChip::default();
    //     let trace: RowMajorMatrix<BabyBear> =
    //         chip.generate_trace(&shard, &mut ExecutionRecord::default());
    //     println!("{:?}", trace.values);
    // }

    #[test]
    fn generate_trace_simple_program() {
        let program = ssz_withdrawals_program();
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        println!("runtime: {:?}", runtime.state.global_clk);
        let chip = CpuChip::default();

        let start = Instant::now();
        <CpuChip as MachineAir<BabyBear>>::generate_dependencies(
            &chip,
            &runtime.record,
            &mut ExecutionRecord::default(),
        );
        println!("generate dependencies: {:?}", start.elapsed());

        let start = Instant::now();
        let _: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&runtime.record, &mut ExecutionRecord::default());
        println!("generate trace: {:?}", start.elapsed());
    }

    #[test]
    fn prove_trace() {
        setup_logger();
        let program = simple_program();
        run_test::<DefaultProver<_, _>>(program).unwrap();
    }
}
