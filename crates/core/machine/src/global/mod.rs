use std::{borrow::Borrow, mem::transmute};

use p3_air::{Air, BaseAir};
use p3_field::{PrimeField, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefMutIterator, ParallelBridge,
    ParallelIterator,
};
use rayon_scan::ScanParallelIterator;
use sp1_core_executor::{events::GlobalInteractionEvent, ExecutionRecord, Program};
use sp1_stark::{
    air::{AirInteraction, InteractionScope, MachineAir, SP1AirBuilder},
    septic_curve::{SepticCurve, SepticCurveComplete},
    septic_digest::SepticDigest,
    septic_extension::{SepticBlock, SepticExtension},
    InteractionKind,
};
use std::borrow::BorrowMut;

use crate::{
    operations::{GlobalAccumulationOperation, GlobalInteractionOperation},
    utils::{next_power_of_two, zeroed_f_vec},
};
use sp1_derive::AlignedBorrow;

const NUM_GLOBAL_COLS: usize = size_of::<GlobalCols<u8>>();

#[derive(Default)]
pub struct GlobalChip;

#[derive(AlignedBorrow, Default)]
#[repr(C)]
pub struct GlobalCols<T: Copy> {
    pub message: [T; 7],
    pub interaction: GlobalInteractionOperation<T>,
    pub is_receive: T,
    pub is_send: T,
    pub is_real: T,
    pub accumulation: GlobalAccumulationOperation<T, 1>,
}

impl<F: PrimeField32> MachineAir<F> for GlobalChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Global".to_string()
    }

    fn generate_trace(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = &input.global_interaction_events;

        let nb_rows = events.len();
        println!("nb_rows: {}", nb_rows);
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_power_of_two(nb_rows, size_log2);
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_GLOBAL_COLS);
        let chunk_size = std::cmp::max(nb_rows / num_cpus::get(), 0) + 1;

        let mut chunks = values[..nb_rows * NUM_GLOBAL_COLS]
            .chunks_mut(chunk_size * NUM_GLOBAL_COLS)
            .collect::<Vec<_>>();

        let point_chunks = chunks
            .par_iter_mut()
            .enumerate()
            .map(|(i, rows)| {
                let mut point_chunks = Vec::with_capacity(chunk_size * NUM_GLOBAL_COLS + 1);
                if i == 0 {
                    point_chunks.push(SepticCurveComplete::Affine(SepticDigest::<F>::zero().0));
                }
                rows.chunks_mut(NUM_GLOBAL_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut GlobalCols<F> = row.borrow_mut();
                    let event: &GlobalInteractionEvent = &events[idx];
                    cols.message = event.message.map(F::from_canonical_u32);
                    cols.interaction.populate(
                        SepticBlock(event.message),
                        event.is_receive,
                        true,
                        InteractionKind::Memory,
                    );
                    cols.is_real = F::one();
                    if event.is_receive {
                        cols.is_receive = F::one();
                    } else {
                        cols.is_send = F::one();
                    }
                    point_chunks.push(SepticCurveComplete::Affine(SepticCurve {
                        x: SepticExtension(cols.interaction.x_coordinate.0),
                        y: SepticExtension(cols.interaction.y_coordinate.0),
                    }));
                });
                point_chunks
            })
            .collect::<Vec<_>>();

        let mut points = point_chunks.into_iter().flatten().collect::<Vec<_>>();

        let cumulative_sum = points
            .into_par_iter()
            .with_min_len(1 << 15)
            .scan(|a, b| *a + *b, SepticCurveComplete::Infinity)
            .collect::<Vec<SepticCurveComplete<F>>>();

        let final_digest = cumulative_sum.last().unwrap().point();
        let dummy = SepticCurve::<F>::dummy();
        let final_sum_checker = SepticCurve::<F>::sum_checker_x(final_digest, dummy, final_digest);

        let chunk_size = std::cmp::max(padded_nb_rows / num_cpus::get(), 0) + 1;
        values.chunks_mut(chunk_size * NUM_GLOBAL_COLS).enumerate().par_bridge().for_each(
            |(i, rows)| {
                rows.chunks_mut(NUM_GLOBAL_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut GlobalCols<F> = row.borrow_mut();
                    if idx < nb_rows {
                        cols.accumulation.populate_real(
                            &cumulative_sum[idx..idx + 2], // TODO: check if this is correct
                            final_digest,
                            final_sum_checker,
                        );
                    } else {
                        cols.interaction.populate_dummy();
                        cols.accumulation.populate_dummy(final_digest, final_sum_checker);
                    }
                });
            },
        );

        RowMajorMatrix::new(values, NUM_GLOBAL_COLS)
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        // TODO: not necessary since only used ofr range checks
    }

    fn included(&self, shard: &Self::Record) -> bool {
        true
    }

    fn commit_scope(&self) -> InteractionScope {
        InteractionScope::Global
    }
}

impl<F> BaseAir<F> for GlobalChip {
    fn width(&self) -> usize {
        NUM_GLOBAL_COLS
    }
}

impl<AB> Air<AB> for GlobalChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &GlobalCols<AB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &GlobalCols<AB::Var> = (*next).borrow();

        builder.receive(
            AirInteraction::new(
                vec![
                    local.message[0].into(),
                    local.message[1].into(),
                    local.message[2].into(),
                    local.message[3].into(),
                    local.message[4].into(),
                    local.message[5].into(),
                    local.message[6].into(),
                    local.is_send.into(),
                    local.is_receive.into(),
                ],
                local.is_real.into(),
                InteractionKind::Memory,
            ),
            InteractionScope::Local,
        );

        GlobalInteractionOperation::<AB::F>::eval_single_digest(
            builder,
            local.message.map(Into::into),
            local.interaction,
            local.is_receive.into(),
            local.is_send.into(),
            local.is_real,
            InteractionKind::Memory,
        );

        GlobalAccumulationOperation::<AB::F, 1>::eval_accumulation(
            builder,
            [local.interaction],
            [local.is_real],
            [next.is_real],
            local.accumulation,
            next.accumulation,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::thread_rng;
    use rand::Rng;
    use sp1_core_executor::events::{MemoryLocalEvent, MemoryRecord};
    use sp1_core_executor::programs::tests::fibonacci_program;
    use sp1_core_executor::{programs::tests::simple_program, ExecutionRecord, Executor};
    use sp1_stark::CpuProver;
    use sp1_stark::{
        air::{InteractionScope, MachineAir},
        baby_bear_poseidon2::BabyBearPoseidon2,
        debug_interactions_with_all_chips, InteractionKind, SP1CoreOpts, StarkMachine,
    };
    use test_artifacts::TENDERMINT_BENCHMARK_ELF;

    use crate::io::SP1Stdin;
    use crate::utils::run_test;
    use crate::{
        memory::MemoryLocalChip, riscv::RiscvAir,
        syscall::precompiles::sha256::extend_tests::sha_extend_program, utils::setup_logger,
    };

    #[test]
    fn test_global_generate_trace() {
        let program = simple_program();
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        let shard = runtime.records[0].clone();

        let chip: GlobalChip = GlobalChip;

        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values);

        for mem_event in shard.global_memory_finalize_events {
            println!("{:?}", mem_event);
        }
    }

    #[test]
    fn test_global_lookup_interactions() {
        setup_logger();
        // let program = sha_extend_program();
        let program = Program::from(TENDERMINT_BENCHMARK_ELF).unwrap();
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
        // debug_interactions_with_all_chips::<BabyBearPoseidon2, RiscvAir<BabyBear>>(
        //     &machine,
        //     &pkey,
        //     &shards,
        //     vec![InteractionKind::Memory],
        //     InteractionScope::Global,
        // );
    }

    #[test]
    fn test_sha_extend() {
        setup_logger();
        let program = Program::from(TENDERMINT_BENCHMARK_ELF).unwrap();
        let input = SP1Stdin::new();
        run_test::<CpuProver<_, _>>(program, input).unwrap();
    }
}
