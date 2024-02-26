use super::columns::{CPU_COL_MAP, NUM_CPU_COLS};
use super::{CpuChip, CpuEvent};
use crate::air::MachineAir;
use crate::alu::{self, AluEvent};
use crate::bytes::{ByteLookupEvent, ByteOpcode};
use crate::cpu::columns::CpuCols;
use crate::cpu::memory::MemoryRecordEnum;
use crate::disassembler::WORD_SIZE;
use crate::field::event::FieldEvent;
use crate::memory::MemoryCols;
use crate::runtime::{ExecutionRecord, Opcode};
use hashbrown::HashMap;
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::IntoParallelRefIterator;
use p3_maybe_rayon::prelude::ParallelIterator;
use p3_maybe_rayon::prelude::ParallelSlice;
use std::borrow::BorrowMut;
use tracing::instrument;

impl<F: PrimeField> MachineAir<F> for CpuChip {
    fn name(&self) -> String {
        "CPU".to_string()
    }

    #[instrument(name = "generate CPU trace", skip_all)]
    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut new_alu_events = HashMap::new();
        let mut new_blu_events = Vec::new();
        let mut new_field_events: Vec<FieldEvent> = Vec::new();

        // Generate the trace rows for each event.
        let rows_with_events = input
            .cpu_events
            .par_iter()
            .map(|op: &CpuEvent| self.event_to_row::<F>(*op))
            .collect::<Vec<_>>();

        let mut rows = Vec::<F>::new();
        rows_with_events.into_iter().for_each(|row_with_events| {
            let (row, alu_events, blu_events, field_events) = row_with_events;
            rows.extend(row);
            for (key, value) in alu_events {
                new_alu_events
                    .entry(key)
                    .and_modify(|op_new_events: &mut Vec<AluEvent>| {
                        op_new_events.extend(value.clone())
                    })
                    .or_insert(value);
            }
            new_blu_events.extend(blu_events);
            new_field_events.extend(field_events);
        });

        // Add the dependency events to the shard.
        output.add_alu_events(new_alu_events);
        output.add_byte_lookup_events(new_blu_events);
        output.add_field_events(&new_field_events);

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(rows, NUM_CPU_COLS);

        // Pad the trace to a power of two.
        Self::pad_to_power_of_two::<F>(&mut trace.values);

        trace
    }

    #[instrument(name = "generate CPU dependencies", skip_all)]
    fn generate_dependencies(&self, input: &ExecutionRecord, output: &mut ExecutionRecord) {
        let mut new_alu_events = HashMap::with_capacity(input.cpu_events.len());
        let mut new_blu_events = Vec::with_capacity(input.cpu_events.len());
        let mut new_field_events: Vec<FieldEvent> = Vec::with_capacity(input.cpu_events.len());

        // Generate the trace rows for each event.
        let chunk_size = std::cmp::max(input.cpu_events.len() / num_cpus::get(), 1);
        let events = input
            .cpu_events
            .par_chunks(chunk_size)
            .map(|ops: &[CpuEvent]| {
                ops.iter()
                    .map(|op| {
                        let (_, alu_events, blu_events, field_events) = self.event_to_row::<F>(*op);
                        (alu_events, blu_events, field_events)
                    })
                    .collect::<Vec<_>>()
            })
            .flatten()
            .collect::<Vec<_>>();

        events.into_iter().for_each(|e| {
            let (alu_events, blu_events, field_events) = e;
            for (key, value) in alu_events {
                new_alu_events
                    .entry(key)
                    .and_modify(|op_new_events: &mut Vec<AluEvent>| {
                        op_new_events.extend(value.clone())
                    })
                    .or_insert(value);
            }
            new_blu_events.extend(blu_events);
            new_field_events.extend(field_events);
        });

        // Add the dependency events to the shard.
        output.add_alu_events(new_alu_events);
        output.add_byte_lookup_events(new_blu_events);
        output.add_field_events(&new_field_events);
    }
}

impl CpuChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField>(
        &self,
        event: CpuEvent,
    ) -> (
        [F; NUM_CPU_COLS],
        HashMap<Opcode, Vec<alu::AluEvent>>,
        Vec<ByteLookupEvent>,
        Vec<FieldEvent>,
    ) {
        let mut new_alu_events = HashMap::new();
        let mut new_blu_events = Vec::new();
        let mut new_field_events = Vec::new();

        let mut row = [F::zero(); NUM_CPU_COLS];
        let cols: &mut CpuCols<F> = row.as_mut_slice().borrow_mut();

        // Populate basic fields.
        cols.shard = F::from_canonical_u32(event.shard);
        cols.clk = F::from_canonical_u32(event.clk);
        cols.pc = F::from_canonical_u32(event.pc);
        cols.instruction.populate(event.instruction);
        cols.selectors.populate(event.instruction);
        *cols.op_a_access.value_mut() = event.a.into();
        *cols.op_b_access.value_mut() = event.b.into();
        *cols.op_c_access.value_mut() = event.c.into();

        // Populate memory accesses for a, b, and c.
        if let Some(record) = event.a_record {
            cols.op_a_access.populate(record, &mut new_field_events)
        }
        if let Some(MemoryRecordEnum::Read(record)) = event.b_record {
            cols.op_b_access.populate(record, &mut new_field_events)
        }
        if let Some(MemoryRecordEnum::Read(record)) = event.c_record {
            cols.op_c_access.populate(record, &mut new_field_events)
        }

        // Populate memory accesses for reading from memory.
        assert_eq!(event.memory_record.is_some(), event.memory.is_some());
        let memory_columns = cols.opcode_specific_columns.memory_mut();
        if let Some(record) = event.memory_record {
            memory_columns
                .memory_access
                .populate(record, &mut new_field_events)
        }

        // Populate memory, branch, jump, and auipc specific fields.
        self.populate_memory(cols, event, &mut new_alu_events, &mut new_blu_events);
        self.populate_branch(cols, event, &mut new_alu_events);
        self.populate_jump(cols, event, &mut new_alu_events);
        self.populate_auipc(cols, event, &mut new_alu_events);

        // Assert that the instruction is not a no-op.
        cols.is_real = F::one();

        (row, new_alu_events, new_blu_events, new_field_events)
    }

    /// Populates columns related to memory.
    fn populate_memory<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: CpuEvent,
        new_alu_events: &mut HashMap<Opcode, Vec<alu::AluEvent>>,
        new_blu_events: &mut Vec<ByteLookupEvent>,
    ) {
        if !matches!(
            event.instruction.opcode,
            Opcode::LB
                | Opcode::LH
                | Opcode::LW
                | Opcode::LBU
                | Opcode::LHU
                | Opcode::SB
                | Opcode::SH
                | Opcode::SW
        ) {
            return;
        }

        // Populate addr_word and addr_aligned columns.
        let memory_columns = cols.opcode_specific_columns.memory_mut();
        let memory_addr = event.b.wrapping_add(event.c);
        memory_columns.addr_word = memory_addr.into();
        memory_columns.addr_aligned =
            F::from_canonical_u32(memory_addr - memory_addr % WORD_SIZE as u32);

        // Add event to ALU check to check that addr == b + c
        let add_event = AluEvent {
            clk: event.clk,
            opcode: Opcode::ADD,
            a: memory_addr,
            b: event.b,
            c: event.c,
        };
        new_alu_events
            .entry(Opcode::ADD)
            .and_modify(|op_new_events| op_new_events.push(add_event))
            .or_insert(vec![add_event]);

        // Populate memory offsets.
        let addr_offset = (memory_addr % WORD_SIZE as u32) as u8;
        memory_columns.addr_offset = F::from_canonical_u8(addr_offset);
        memory_columns.offset_is_one = F::from_bool(addr_offset == 1);
        memory_columns.offset_is_two = F::from_bool(addr_offset == 2);
        memory_columns.offset_is_three = F::from_bool(addr_offset == 3);

        // If it is a load instruction, set the unsigned_mem_val column.
        let mem_value = event.memory_record.unwrap().value();
        if matches!(
            event.instruction.opcode,
            Opcode::LB | Opcode::LBU | Opcode::LH | Opcode::LHU | Opcode::LW
        ) {
            match event.instruction.opcode {
                Opcode::LB | Opcode::LBU => {
                    cols.unsigned_mem_val =
                        (mem_value.to_le_bytes()[addr_offset as usize] as u32).into();
                }
                Opcode::LH | Opcode::LHU => {
                    let value = match (addr_offset >> 1) % 2 {
                        0 => mem_value & 0x0000FFFF,
                        1 => (mem_value & 0xFFFF0000) >> 16,
                        _ => unreachable!(),
                    };
                    cols.unsigned_mem_val = value.into();
                }
                Opcode::LW => {
                    cols.unsigned_mem_val = mem_value.into();
                }
                _ => unreachable!(),
            }

            // For the signed load instructions, we need to check if the loaded value is negative.
            if matches!(event.instruction.opcode, Opcode::LB | Opcode::LH) {
                let most_sig_mem_value_byte: u8;
                let sign_value: u32;
                if matches!(event.instruction.opcode, Opcode::LB) {
                    sign_value = 256;
                    most_sig_mem_value_byte = cols.unsigned_mem_val.to_u32().to_le_bytes()[0];
                } else {
                    // LHU case
                    sign_value = 65536;
                    most_sig_mem_value_byte = cols.unsigned_mem_val.to_u32().to_le_bytes()[1];
                };

                for i in (0..8).rev() {
                    memory_columns.most_sig_byte_decomp[i] =
                        F::from_canonical_u8(most_sig_mem_value_byte >> i & 0x01);
                }
                if memory_columns.most_sig_byte_decomp[7] == F::one() {
                    cols.mem_value_is_neg = F::one();
                    let sub_event = AluEvent {
                        clk: event.clk,
                        opcode: Opcode::SUB,
                        a: event.a,
                        b: cols.unsigned_mem_val.to_u32(),
                        c: sign_value,
                    };

                    new_alu_events
                        .entry(Opcode::SUB)
                        .and_modify(|op_new_events| op_new_events.push(sub_event))
                        .or_insert(vec![sub_event]);
                }
            }
        }

        // Add event to byte lookup for byte range checking each byte in the memory addr
        let addr_bytes = memory_addr.to_le_bytes();
        for byte_pair in addr_bytes.chunks_exact(2) {
            new_blu_events.push(ByteLookupEvent {
                opcode: ByteOpcode::U8Range,
                a1: 0,
                a2: 0,
                b: byte_pair[0] as u32,
                c: byte_pair[1] as u32,
            });
        }
    }

    /// Populates columns related to branching.
    fn populate_branch<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: CpuEvent,
        alu_events: &mut HashMap<Opcode, Vec<alu::AluEvent>>,
    ) {
        if event.instruction.is_branch_instruction() {
            let branch_columns = cols.opcode_specific_columns.branch_mut();

            let a_eq_b = event.a == event.b;

            let use_signed_comparison =
                matches!(event.instruction.opcode, Opcode::BLT | Opcode::BGE);

            let a_lt_b = if use_signed_comparison {
                (event.a as i32) < (event.b as i32)
            } else {
                event.a < event.b
            };
            let a_gt_b = if use_signed_comparison {
                (event.a as i32) > (event.b as i32)
            } else {
                event.a > event.b
            };

            let alu_op_code = if use_signed_comparison {
                Opcode::SLT
            } else {
                Opcode::SLTU
            };
            // Add the ALU events for the comparisons
            let lt_comp_event = AluEvent {
                clk: event.clk,
                opcode: alu_op_code,
                a: a_lt_b as u32,
                b: event.a,
                c: event.b,
            };

            alu_events
                .entry(alu_op_code)
                .and_modify(|op_new_events| op_new_events.push(lt_comp_event))
                .or_insert(vec![lt_comp_event]);

            let gt_comp_event = AluEvent {
                clk: event.clk,
                opcode: alu_op_code,
                a: a_gt_b as u32,
                b: event.b,
                c: event.a,
            };

            alu_events
                .entry(alu_op_code)
                .and_modify(|op_new_events| op_new_events.push(gt_comp_event))
                .or_insert(vec![gt_comp_event]);

            branch_columns.a_eq_b = F::from_bool(a_eq_b);
            branch_columns.a_lt_b = F::from_bool(a_lt_b);
            branch_columns.a_gt_b = F::from_bool(a_gt_b);

            let branching = match event.instruction.opcode {
                Opcode::BEQ => a_eq_b,
                Opcode::BNE => !a_eq_b,
                Opcode::BLT | Opcode::BLTU => a_lt_b,
                Opcode::BGE | Opcode::BGEU => a_eq_b || a_gt_b,
                _ => unreachable!(),
            };

            if branching {
                let next_pc = event.pc.wrapping_add(event.c);

                cols.branching = F::one();
                branch_columns.pc = event.pc.into();
                branch_columns.next_pc = next_pc.into();

                let add_event = AluEvent {
                    clk: event.clk,
                    opcode: Opcode::ADD,
                    a: next_pc,
                    b: event.pc,
                    c: event.c,
                };

                alu_events
                    .entry(Opcode::ADD)
                    .and_modify(|op_new_events| op_new_events.push(add_event))
                    .or_insert(vec![add_event]);
            } else {
                cols.not_branching = F::one();
            }
        }
    }

    /// Populate columns related to jumping.
    fn populate_jump<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: CpuEvent,
        alu_events: &mut HashMap<Opcode, Vec<alu::AluEvent>>,
    ) {
        if event.instruction.is_jump_instruction() {
            let jump_columns = cols.opcode_specific_columns.jump_mut();

            match event.instruction.opcode {
                Opcode::JAL => {
                    let next_pc = event.pc.wrapping_add(event.b);
                    jump_columns.pc = event.pc.into();
                    jump_columns.next_pc = next_pc.into();

                    let add_event = AluEvent {
                        clk: event.clk,
                        opcode: Opcode::ADD,
                        a: next_pc,
                        b: event.pc,
                        c: event.b,
                    };

                    alu_events
                        .entry(Opcode::ADD)
                        .and_modify(|op_new_events| op_new_events.push(add_event))
                        .or_insert(vec![add_event]);
                }
                Opcode::JALR => {
                    let next_pc = event.b.wrapping_add(event.c);
                    jump_columns.next_pc = next_pc.into();

                    let add_event = AluEvent {
                        clk: event.clk,
                        opcode: Opcode::ADD,
                        a: next_pc,
                        b: event.b,
                        c: event.c,
                    };

                    alu_events
                        .entry(Opcode::ADD)
                        .and_modify(|op_new_events| op_new_events.push(add_event))
                        .or_insert(vec![add_event]);
                }
                _ => unreachable!(),
            }
        }
    }

    /// Populate columns related to AUIPC.
    fn populate_auipc<F: PrimeField>(
        &self,
        cols: &mut CpuCols<F>,
        event: CpuEvent,
        alu_events: &mut HashMap<Opcode, Vec<alu::AluEvent>>,
    ) {
        if matches!(event.instruction.opcode, Opcode::AUIPC) {
            let auipc_columns = cols.opcode_specific_columns.auipc_mut();

            auipc_columns.pc = event.pc.into();

            let add_event = AluEvent {
                clk: event.clk,
                opcode: Opcode::ADD,
                a: event.a,
                b: event.pc,
                c: event.b,
            };

            alu_events
                .entry(Opcode::ADD)
                .and_modify(|op_new_events| op_new_events.push(add_event))
                .or_insert(vec![add_event]);
        }
    }

    fn pad_to_power_of_two<F: PrimeField>(values: &mut Vec<F>) {
        let len: usize = values.len();
        let n_real_rows = values.len() / NUM_CPU_COLS;
        let last_row = &values[len - NUM_CPU_COLS..];
        let pc = last_row[CPU_COL_MAP.pc];
        let clk = last_row[CPU_COL_MAP.clk];

        values.resize(n_real_rows.next_power_of_two() * NUM_CPU_COLS, F::zero());

        // Interpret values as a slice of arrays of length `NUM_CPU_COLS`
        let rows = unsafe {
            core::slice::from_raw_parts_mut(
                values.as_mut_ptr() as *mut [F; NUM_CPU_COLS],
                values.len() / NUM_CPU_COLS,
            )
        };

        rows[n_real_rows..]
            .iter_mut()
            .enumerate()
            .for_each(|(n, padded_row)| {
                padded_row[CPU_COL_MAP.pc] = pc;
                padded_row[CPU_COL_MAP.clk] = clk + F::from_canonical_u32((n as u32 + 1) * 4);
                padded_row[CPU_COL_MAP.selectors.is_noop] = F::one();
                padded_row[CPU_COL_MAP.selectors.imm_b] = F::one();
                padded_row[CPU_COL_MAP.selectors.imm_c] = F::one();
            });
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;

    use super::*;

    use crate::utils::{uni_stark_prove as prove, uni_stark_verify as verify};
    use crate::{
        runtime::{tests::simple_program, ExecutionRecord, Instruction, Runtime},
        utils::{BabyBearPoseidon2, StarkUtils},
    };

    #[test]
    fn generate_trace() {
        let mut shard = ExecutionRecord::default();
        shard.cpu_events = vec![CpuEvent {
            shard: 1,
            clk: 6,
            pc: 1,
            instruction: Instruction {
                opcode: Opcode::ADD,
                op_a: 0,
                op_b: 1,
                op_c: 2,
                imm_b: false,
                imm_c: false,
            },
            a: 1,
            a_record: None,
            b: 2,
            b_record: None,
            c: 3,
            c_record: None,
            memory: None,
            memory_record: None,
        }];
        let chip = CpuChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values);
    }

    #[test]
    fn generate_trace_simple_program() {
        let program = simple_program();
        let mut runtime = Runtime::new(program);
        runtime.run();
        let chip = CpuChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&runtime.record, &mut ExecutionRecord::default());
        for cpu_event in runtime.record.cpu_events {
            println!("{:?}", cpu_event);
        }
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_trace() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let program = simple_program();
        let mut runtime = Runtime::new(program);
        runtime.run();
        let chip = CpuChip::default();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&runtime.record, &mut ExecutionRecord::default());
        trace.rows().for_each(|row| println!("{:?}", row));

        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
