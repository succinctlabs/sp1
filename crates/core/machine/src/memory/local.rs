use std::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use crate::utils::{next_power_of_two, zeroed_f_vec};
use crate::{operations::GlobalAccumulationOperation, operations::GlobalInteractionOperation};
use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::{Air, BaseAir};
use p3_field::AbstractExtensionField;
use p3_field::PrimeField32;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::{ParallelBridge, ParallelIterator};
use sp1_core_executor::events::ByteLookupEvent;
use sp1_core_executor::events::ByteRecord;
use sp1_core_executor::{ExecutionRecord, Program};
use sp1_derive::AlignedBorrow;
use sp1_stark::septic_curve::SepticCurve;
use sp1_stark::septic_extension::SepticExtension;
use sp1_stark::{
    air::{AirInteraction, InteractionScope, MachineAir, SP1AirBuilder},
    septic_digest::CURVE_CUMULATIVE_SUM_START_X,
    septic_digest::CURVE_CUMULATIVE_SUM_START_Y,
    InteractionKind, Word,
};
pub const NUM_LOCAL_MEMORY_ENTRIES_PER_ROW: usize = 4;

pub(crate) const NUM_MEMORY_LOCAL_INIT_COLS: usize = size_of::<MemoryLocalCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
struct SingleMemoryLocal<T> {
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

    /// The global interaction columns for initial access.
    pub initial_global_interaction_cols: GlobalInteractionOperation<T>,

    /// The global interaction columns for final access.
    pub final_global_interaction_cols: GlobalInteractionOperation<T>,

    /// Whether the memory access is a real access.
    pub is_real: T,
}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryLocalCols<T> {
    memory_local_entries: [SingleMemoryLocal<T>; NUM_LOCAL_MEMORY_ENTRIES_PER_ROW],
    pub global_accumulation_cols: GlobalAccumulationOperation<T, 8>,
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

impl<F: PrimeField32> MachineAir<F> for MemoryLocalChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "MemoryLocal".to_string()
    }

    fn generate_dependencies(&self, input: &ExecutionRecord, output: &mut ExecutionRecord) {
        let mut blu: HashMap<u32, HashMap<ByteLookupEvent, usize>> = HashMap::new();
        for local_mem_events in
            &input.get_local_mem_events().chunks(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW)
        {
            let mut row = [F::zero(); NUM_MEMORY_LOCAL_INIT_COLS];
            let cols: &mut MemoryLocalCols<F> = row.as_mut_slice().borrow_mut();

            for (cols, event) in cols.memory_local_entries.iter_mut().zip(local_mem_events) {
                cols.initial_global_interaction_cols.populate_memory(
                    event.initial_mem_access.shard,
                    event.initial_mem_access.timestamp,
                    event.addr,
                    event.initial_mem_access.value,
                    true,
                    true,
                    &mut blu,
                );
                cols.final_global_interaction_cols.populate_memory(
                    event.final_mem_access.shard,
                    event.final_mem_access.timestamp,
                    event.addr,
                    event.final_mem_access.value,
                    false,
                    true,
                    &mut blu,
                );
            }
        }
        output.add_sharded_byte_lookup_events(vec![&blu]);
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let events = input.get_local_mem_events().collect::<Vec<_>>();
        let nb_rows = (events.len() + 3) / 4;
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_power_of_two(nb_rows, size_log2);
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_MEMORY_LOCAL_INIT_COLS);
        let chunk_size = std::cmp::max((nb_rows + 1) / num_cpus::get(), 1);

        values
            .chunks_mut(chunk_size * NUM_MEMORY_LOCAL_INIT_COLS)
            .enumerate()
            .par_bridge()
            .for_each(|(i, rows)| {
                rows.chunks_mut(NUM_MEMORY_LOCAL_INIT_COLS).enumerate().for_each(|(j, row)| {
                    let idx = (i * chunk_size + j) * NUM_LOCAL_MEMORY_ENTRIES_PER_ROW;

                    let cols: &mut MemoryLocalCols<F> = row.borrow_mut();
                    for k in 0..NUM_LOCAL_MEMORY_ENTRIES_PER_ROW {
                        let cols = &mut cols.memory_local_entries[k];
                        if idx + k < events.len() {
                            let event = &events[idx + k];
                            cols.addr = F::from_canonical_u32(event.addr);
                            cols.initial_shard =
                                F::from_canonical_u32(event.initial_mem_access.shard);
                            cols.final_shard = F::from_canonical_u32(event.final_mem_access.shard);
                            cols.initial_clk =
                                F::from_canonical_u32(event.initial_mem_access.timestamp);
                            cols.final_clk =
                                F::from_canonical_u32(event.final_mem_access.timestamp);
                            cols.initial_value = event.initial_mem_access.value.into();
                            cols.final_value = event.final_mem_access.value.into();
                            cols.is_real = F::one();
                            let mut blu = Vec::new();
                            cols.initial_global_interaction_cols.populate_memory(
                                event.initial_mem_access.shard,
                                event.initial_mem_access.timestamp,
                                event.addr,
                                event.initial_mem_access.value,
                                true,
                                true,
                                &mut blu,
                            );
                            cols.final_global_interaction_cols.populate_memory(
                                event.final_mem_access.shard,
                                event.final_mem_access.timestamp,
                                event.addr,
                                event.final_mem_access.value,
                                false,
                                true,
                                &mut blu,
                            );
                        }
                    }
                });
            });

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(values, NUM_MEMORY_LOCAL_INIT_COLS);

        for i in 0..trace.height() {
            if (i + 1) * NUM_LOCAL_MEMORY_ENTRIES_PER_ROW < events.len() {
                continue;
            }
            let cols: &mut MemoryLocalCols<F> = trace.values
                [i * NUM_MEMORY_LOCAL_INIT_COLS..(i + 1) * NUM_MEMORY_LOCAL_INIT_COLS]
                .borrow_mut();
            for (idx, cols) in cols.memory_local_entries.iter_mut().enumerate() {
                if i * NUM_LOCAL_MEMORY_ENTRIES_PER_ROW + idx >= events.len() {
                    cols.initial_global_interaction_cols.populate_dummy();
                    cols.final_global_interaction_cols.populate_dummy();
                }
            }
        }

        let mut global_cumulative_sum = SepticCurve {
            x: SepticExtension::<F>::from_base_fn(|i| {
                F::from_canonical_u32(CURVE_CUMULATIVE_SUM_START_X[i])
            }),
            y: SepticExtension::<F>::from_base_fn(|i| {
                F::from_canonical_u32(CURVE_CUMULATIVE_SUM_START_Y[i])
            }),
        };

        for i in 0..trace.height() {
            let cols: &mut MemoryLocalCols<F> = trace.values
                [i * NUM_MEMORY_LOCAL_INIT_COLS..(i + 1) * NUM_MEMORY_LOCAL_INIT_COLS]
                .borrow_mut();
            let mut global_interaction_cols = Vec::new();
            let mut is_reals = Vec::new();
            for idx in 0..NUM_LOCAL_MEMORY_ENTRIES_PER_ROW {
                global_interaction_cols
                    .push(cols.memory_local_entries[idx].initial_global_interaction_cols);
                global_interaction_cols
                    .push(cols.memory_local_entries[idx].final_global_interaction_cols);
                is_reals.push(cols.memory_local_entries[idx].is_real);
                is_reals.push(cols.memory_local_entries[idx].is_real);
            }

            cols.global_accumulation_cols.populate(
                &mut global_cumulative_sum,
                global_interaction_cols.try_into().unwrap(),
                is_reals.try_into().unwrap(),
            );
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            shard.get_local_mem_events().nth(0).is_some()
        }
    }

    fn commit_scope(&self) -> InteractionScope {
        InteractionScope::Global
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
        let next = main.row_slice(1);
        let next: &MemoryLocalCols<AB::Var> = (*next).borrow();

        let mut global_interaction_cols = Vec::new();
        let mut local_is_reals = Vec::new();
        let mut next_is_reals = Vec::new();

        for local in local.memory_local_entries.iter() {
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

            GlobalInteractionOperation::<AB::F>::eval_single_digest(
                builder,
                values,
                local.initial_global_interaction_cols,
                true,
                local.is_real,
                InteractionKind::Memory,
            );

            global_interaction_cols.push(local.initial_global_interaction_cols);
            local_is_reals.push(local.is_real);

            let mut values =
                vec![local.final_shard.into(), local.final_clk.into(), local.addr.into()];
            values.extend(local.final_value.map(Into::into));
            builder.send(
                AirInteraction::new(values.clone(), local.is_real.into(), InteractionKind::Memory),
                InteractionScope::Local,
            );

            GlobalInteractionOperation::<AB::F>::eval_single_digest(
                builder,
                values,
                local.final_global_interaction_cols,
                false,
                local.is_real,
                InteractionKind::Memory,
            );

            global_interaction_cols.push(local.final_global_interaction_cols);
            local_is_reals.push(local.is_real);
        }

        for next in next.memory_local_entries.iter() {
            next_is_reals.push(next.is_real);
            next_is_reals.push(next.is_real);
        }

        GlobalAccumulationOperation::<AB::F, 8>::eval_accumulation(
            builder,
            global_interaction_cols
                .try_into()
                .unwrap_or_else(|_| panic!("There should be 8 interactions")),
            local_is_reals.try_into().unwrap_or_else(|_| panic!("There should be 8 interactions")),
            next_is_reals.try_into().unwrap_or_else(|_| panic!("There should be 8 interactions")),
            local.global_accumulation_cols,
            next.global_accumulation_cols,
        );
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use sp1_core_executor::{programs::tests::simple_program, ExecutionRecord, Executor};
    use sp1_stark::{
        air::{InteractionScope, MachineAir},
        baby_bear_poseidon2::BabyBearPoseidon2,
        debug_interactions_with_all_chips, InteractionKind, SP1CoreOpts, StarkMachine,
    };

    use crate::{
        memory::MemoryLocalChip, riscv::RiscvAir,
        syscall::precompiles::sha256::extend_tests::sha_extend_program, utils::setup_logger,
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
        machine.generate_dependencies(&mut runtime.records, &opts, None);

        let shards = runtime.records;
        for shard in shards.clone() {
            debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
                &machine,
                &pkey,
                &[shard],
                vec![InteractionKind::Memory],
                InteractionScope::Local,
            );
        }
        debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
            &machine,
            &pkey,
            &shards,
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
        machine.generate_dependencies(&mut runtime.records, &opts, None);

        let shards = runtime.records;
        for shard in shards.clone() {
            debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
                &machine,
                &pkey,
                &[shard],
                vec![InteractionKind::Memory],
                InteractionScope::Local,
            );
        }
        debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
            &machine,
            &pkey,
            &shards,
            vec![InteractionKind::Byte],
            InteractionScope::Global,
        );
    }
}
