use std::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use crate::utils::{next_power_of_two, zeroed_f_vec};

use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::{
    IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use sp1_core_executor::events::GlobalInteractionEvent;
use sp1_core_executor::{ExecutionRecord, Program};
use sp1_derive::AlignedBorrow;
use sp1_stark::{
    air::{AirInteraction, InteractionScope, MachineAir, SP1AirBuilder},
    InteractionKind, Word,
};

pub const NUM_LOCAL_MEMORY_ENTRIES_PER_ROW: usize = 4;
// pub const NUM_LOCAL_MEMORY_INTERACTIONS_PER_ROW: usize = NUM_LOCAL_MEMORY_ENTRIES_PER_ROW * 2;
pub(crate) const NUM_MEMORY_LOCAL_INIT_COLS: usize = size_of::<MemoryLocalCols<u8>>();

// const_assert!(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW_EXEC == NUM_LOCAL_MEMORY_ENTRIES_PER_ROW);

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct SingleMemoryLocal<T: Copy> {
    /// The address of the memory access.
    pub addr: T,

    /// The initial shard of the memory access.
    pub initial_shard: T,

    /// The final shard of the memory access.
    pub final_shard: T,

    /// The initial clk of the memory access.
    pub initial_clk: T,

    /// The final clk of the memory access.
    pub final_clk: T,

    /// The initial value of the memory access.
    pub initial_value: Word<T>,

    /// The final value of the memory access.
    pub final_value: Word<T>,

    /// Whether the memory access is a real access.
    pub is_real: T,
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct MemoryLocalCols<T: Copy> {
    memory_local_entries: [SingleMemoryLocal<T>; NUM_LOCAL_MEMORY_ENTRIES_PER_ROW],
}

pub struct MemoryLocalChip {}

impl MemoryLocalChip {
    /// Creates a new memory chip with a certain type.
    pub const fn new() -> Self {
        Self {}
    }
}

impl<F> BaseAir<F> for MemoryLocalChip {
    fn width(&self) -> usize {
        NUM_MEMORY_LOCAL_INIT_COLS
    }
}

fn nb_rows(count: usize) -> usize {
    if NUM_LOCAL_MEMORY_ENTRIES_PER_ROW > 1 {
        count.div_ceil(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW)
    } else {
        count
    }
}

impl<F: PrimeField32> MachineAir<F> for MemoryLocalChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "MemoryLocal".to_string()
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let mut events = Vec::new();

        input.get_local_mem_events().for_each(|mem_event| {
            events.push(GlobalInteractionEvent {
                message: [
                    mem_event.initial_mem_access.shard,
                    mem_event.initial_mem_access.timestamp,
                    mem_event.addr,
                    mem_event.initial_mem_access.value & 255,
                    (mem_event.initial_mem_access.value >> 8) & 255,
                    (mem_event.initial_mem_access.value >> 16) & 255,
                    (mem_event.initial_mem_access.value >> 24) & 255,
                ],
                is_receive: true,
                kind: InteractionKind::Memory as u8,
            });
            events.push(GlobalInteractionEvent {
                message: [
                    mem_event.final_mem_access.shard,
                    mem_event.final_mem_access.timestamp,
                    mem_event.addr,
                    mem_event.final_mem_access.value & 255,
                    (mem_event.final_mem_access.value >> 8) & 255,
                    (mem_event.final_mem_access.value >> 16) & 255,
                    (mem_event.final_mem_access.value >> 24) & 255,
                ],
                is_receive: false,
                kind: InteractionKind::Memory as u8,
            });
        });

        output.global_interaction_events.extend(events);
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let count = input.get_local_mem_events().count();
        let nb_rows = nb_rows(count);
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        Some(next_power_of_two(nb_rows, size_log2))
    }

    fn generate_trace(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
    ) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let events = input.get_local_mem_events().collect::<Vec<_>>();
        let nb_rows = nb_rows(events.len());
        let padded_nb_rows = <MemoryLocalChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_MEMORY_LOCAL_INIT_COLS);
        let chunk_size = std::cmp::max(nb_rows / num_cpus::get(), 0) + 1;

        let mut chunks = values[..nb_rows * NUM_MEMORY_LOCAL_INIT_COLS]
            .chunks_mut(chunk_size * NUM_MEMORY_LOCAL_INIT_COLS)
            .collect::<Vec<_>>();

        chunks.par_iter_mut().enumerate().for_each(|(i, rows)| {
            rows.chunks_mut(NUM_MEMORY_LOCAL_INIT_COLS).enumerate().for_each(|(j, row)| {
                let idx = (i * chunk_size + j) * NUM_LOCAL_MEMORY_ENTRIES_PER_ROW;

                let cols: &mut MemoryLocalCols<F> = row.borrow_mut();
                for k in 0..NUM_LOCAL_MEMORY_ENTRIES_PER_ROW {
                    let cols = &mut cols.memory_local_entries[k];
                    if idx + k < events.len() {
                        let event = &events[idx + k];
                        cols.addr = F::from_canonical_u32(event.addr);
                        cols.initial_shard = F::from_canonical_u32(event.initial_mem_access.shard);
                        cols.final_shard = F::from_canonical_u32(event.final_mem_access.shard);
                        cols.initial_clk =
                            F::from_canonical_u32(event.initial_mem_access.timestamp);
                        cols.final_clk = F::from_canonical_u32(event.final_mem_access.timestamp);
                        cols.initial_value = event.initial_mem_access.value.into();
                        cols.final_value = event.final_mem_access.value.into();
                        cols.is_real = F::one();
                    }
                }
            });
        });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_MEMORY_LOCAL_INIT_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            shard.get_local_mem_events().nth(0).is_some()
        }
    }

    fn commit_scope(&self) -> InteractionScope {
        InteractionScope::Local
    }
}

impl<AB> Air<AB> for MemoryLocalChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MemoryLocalCols<AB::Var> = (*local).borrow();

        for local in local.memory_local_entries.iter() {
            // Constrain that `local.is_real` is boolean.
            builder.assert_bool(local.is_real);

            builder.assert_eq(
                local.is_real * local.is_real * local.is_real,
                local.is_real * local.is_real * local.is_real,
            );

            let mut values =
                vec![local.initial_shard.into(), local.initial_clk.into(), local.addr.into()];
            values.extend(local.initial_value.map(Into::into));
            builder.receive(
                AirInteraction::new(values.clone(), local.is_real.into(), InteractionKind::Memory),
                InteractionScope::Local,
            );

            // Send the "receive interaction" to the global table.
            builder.send(
                AirInteraction::new(
                    vec![
                        local.initial_shard.into(),
                        local.initial_clk.into(),
                        local.addr.into(),
                        local.initial_value[0].into(),
                        local.initial_value[1].into(),
                        local.initial_value[2].into(),
                        local.initial_value[3].into(),
                        AB::Expr::zero(),
                        AB::Expr::one(),
                        AB::Expr::from_canonical_u8(InteractionKind::Memory as u8),
                    ],
                    local.is_real.into(),
                    InteractionKind::Global,
                ),
                InteractionScope::Local,
            );

            // Send the "send interaction" to the global table.
            builder.send(
                AirInteraction::new(
                    vec![
                        local.final_shard.into(),
                        local.final_clk.into(),
                        local.addr.into(),
                        local.final_value[0].into(),
                        local.final_value[1].into(),
                        local.final_value[2].into(),
                        local.final_value[3].into(),
                        AB::Expr::one(),
                        AB::Expr::zero(),
                        AB::Expr::from_canonical_u8(InteractionKind::Memory as u8),
                    ],
                    local.is_real.into(),
                    InteractionKind::Global,
                ),
                InteractionScope::Local,
            );

            let mut values =
                vec![local.final_shard.into(), local.final_clk.into(), local.addr.into()];
            values.extend(local.final_value.map(Into::into));
            builder.send(
                AirInteraction::new(values.clone(), local.is_real.into(), InteractionKind::Memory),
                InteractionScope::Local,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::print_stdout)]

    use crate::programs::tests::*;
    use crate::{
        memory::MemoryLocalChip, riscv::RiscvAir,
        syscall::precompiles::sha256::extend_tests::sha_extend_program, utils::setup_logger,
    };
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use sp1_core_executor::{ExecutionRecord, Executor};
    use sp1_stark::{
        air::{InteractionScope, MachineAir},
        baby_bear_poseidon2::BabyBearPoseidon2,
        debug_interactions_with_all_chips, InteractionKind, SP1CoreOpts, StarkMachine,
    };

    #[test]
    fn test_local_memory_generate_trace() {
        let program = simple_program();
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        let shard = runtime.records[0].clone();

        let chip: MemoryLocalChip = MemoryLocalChip::new();

        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values);

        for mem_event in shard.global_memory_finalize_events {
            println!("{:?}", mem_event);
        }
    }

    #[test]
    fn test_memory_lookup_interactions() {
        setup_logger();
        let program = sha_extend_program();
        let program_clone = program.clone();
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        let machine: StarkMachine<BabyBearPoseidon2, RiscvAir<BabyBear>> =
            RiscvAir::machine(BabyBearPoseidon2::new());
        let (pkey, _) = machine.setup(&program_clone);
        let opts = SP1CoreOpts::default();
        machine.generate_dependencies(
            &mut runtime.records.clone().into_iter().map(|r| *r).collect::<Vec<_>>(),
            &opts,
            None,
        );

        let shards = runtime.records;
        for shard in shards.clone() {
            debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
                &machine,
                &pkey,
                &[*shard],
                vec![InteractionKind::Memory],
                InteractionScope::Local,
            );
        }
        debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
            &machine,
            &pkey,
            &shards.into_iter().map(|r| *r).collect::<Vec<_>>(),
            vec![InteractionKind::Memory],
            InteractionScope::Global,
        );
    }

    #[test]
    fn test_byte_lookup_interactions() {
        setup_logger();
        let program = sha_extend_program();
        let program_clone = program.clone();
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        let machine = RiscvAir::machine(BabyBearPoseidon2::new());
        let (pkey, _) = machine.setup(&program_clone);
        let opts = SP1CoreOpts::default();
        machine.generate_dependencies(
            &mut runtime.records.clone().into_iter().map(|r| *r).collect::<Vec<_>>(),
            &opts,
            None,
        );

        let shards = runtime.records;
        for shard in shards.clone() {
            debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
                &machine,
                &pkey,
                &[*shard],
                vec![InteractionKind::Memory],
                InteractionScope::Local,
            );
        }
        debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
            &machine,
            &pkey,
            &shards.into_iter().map(|r| *r).collect::<Vec<_>>(),
            vec![InteractionKind::Byte],
            InteractionScope::Global,
        );
    }

    #[cfg(feature = "sys")]
    fn get_test_execution_record() -> ExecutionRecord {
        use p3_field::PrimeField32;
        use rand::{thread_rng, Rng};
        use sp1_core_executor::events::{MemoryLocalEvent, MemoryRecord};

        let cpu_local_memory_access = (0..=255)
            .flat_map(|_| {
                [{
                    let addr = thread_rng().gen_range(0..BabyBear::ORDER_U32);
                    let init_value = thread_rng().gen_range(0..u32::MAX);
                    let init_shard = thread_rng().gen_range(0..(1u32 << 16));
                    let init_timestamp = thread_rng().gen_range(0..(1u32 << 24));
                    let final_value = thread_rng().gen_range(0..u32::MAX);
                    let final_timestamp = thread_rng().gen_range(0..(1u32 << 24));
                    let final_shard = thread_rng().gen_range(0..(1u32 << 16));
                    MemoryLocalEvent {
                        addr,
                        initial_mem_access: MemoryRecord {
                            shard: init_shard,
                            timestamp: init_timestamp,
                            value: init_value,
                        },
                        final_mem_access: MemoryRecord {
                            shard: final_shard,
                            timestamp: final_timestamp,
                            value: final_value,
                        },
                    }
                }]
            })
            .collect::<Vec<_>>();
        ExecutionRecord { cpu_local_memory_access, ..Default::default() }
    }

    #[cfg(feature = "sys")]
    #[test]
    fn test_generate_trace_ffi_eq_rust() {
        use p3_matrix::Matrix;

        let record = get_test_execution_record();
        let chip = MemoryLocalChip::new();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&record, &mut ExecutionRecord::default());
        let trace_ffi = generate_trace_ffi(&record, trace.height());

        assert_eq!(trace_ffi, trace);
    }

    #[cfg(feature = "sys")]
    fn generate_trace_ffi(input: &ExecutionRecord, height: usize) -> RowMajorMatrix<BabyBear> {
        use std::borrow::BorrowMut;

        use rayon::iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};

        use crate::{
            memory::{
                MemoryLocalCols, NUM_LOCAL_MEMORY_ENTRIES_PER_ROW, NUM_MEMORY_LOCAL_INIT_COLS,
            },
            utils::zeroed_f_vec,
        };

        type F = BabyBear;
        // Generate the trace rows for each event.
        let events = input.get_local_mem_events().collect::<Vec<_>>();
        let nb_rows = (events.len() + 3) / 4;
        let padded_nb_rows = height;
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_MEMORY_LOCAL_INIT_COLS);
        let chunk_size = std::cmp::max(nb_rows / num_cpus::get(), 0) + 1;

        let mut chunks = values[..nb_rows * NUM_MEMORY_LOCAL_INIT_COLS]
            .chunks_mut(chunk_size * NUM_MEMORY_LOCAL_INIT_COLS)
            .collect::<Vec<_>>();

        chunks.par_iter_mut().enumerate().for_each(|(i, rows)| {
            rows.chunks_mut(NUM_MEMORY_LOCAL_INIT_COLS).enumerate().for_each(|(j, row)| {
                let idx = (i * chunk_size + j) * NUM_LOCAL_MEMORY_ENTRIES_PER_ROW;
                let cols: &mut MemoryLocalCols<F> = row.borrow_mut();
                for k in 0..NUM_LOCAL_MEMORY_ENTRIES_PER_ROW {
                    let cols = &mut cols.memory_local_entries[k];
                    if idx + k < events.len() {
                        unsafe {
                            crate::sys::memory_local_event_to_row_babybear(events[idx + k], cols);
                        }
                    }
                }
            });
        });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_MEMORY_LOCAL_INIT_COLS)
    }
}
