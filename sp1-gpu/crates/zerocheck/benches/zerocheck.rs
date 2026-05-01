//! Bench `zerocheck` using real Fibonacci ELF traces.
//!
//! Setup mirrors the `test_zerocheck_real_traces` test inside the crate. The trace, chip cache,
//! batched challenges, evaluation point, and `LogUpEvaluations` are all built once before the
//! bench loop. Per-iteration setup only clones the inputs that `zerocheck` consumes by value
//! (public values, challenger), so the timed routine contains only the call.

use std::collections::BTreeMap;
use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use slop_air::BaseAir;
use slop_algebra::AbstractField;
use slop_challenger::{CanObserve, CanSample, FieldChallenger, IopCtx};
use slop_futures::queue::WorkerQueue;
use slop_multilinear::{MleEval, Point};
use slop_tensor::Tensor;
use sp1_core_machine::io::SP1Stdin;
use sp1_gpu_air::codegen_cuda_eval;
use sp1_gpu_cudart::{run_in_place, PinnedBuffer};
use sp1_gpu_jagged_tracegen::test_utils::tracegen_setup::{
    self, CORE_MAX_LOG_ROW_COUNT, LOG_STACKING_HEIGHT,
};
use sp1_gpu_jagged_tracegen::{full_tracegen, CORE_MAX_TRACE_SIZE};
use sp1_gpu_utils::{Ext, Felt, TestGC};
use sp1_gpu_zerocheck::primitives::evaluate_jagged_columns;
use sp1_gpu_zerocheck::zerocheck;
use sp1_hypercube::air::MachineAir;
use sp1_hypercube::prover::ProverSemaphore;
use sp1_hypercube::{ChipEvaluation, LogUpEvaluations};

fn bench_zerocheck(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (machine, record, program) =
            tracegen_setup::setup(&test_artifacts::FIBONACCI_ELF, SP1Stdin::new()).await;

        run_in_place(|scope| async move {
            let mut rng = StdRng::seed_from_u64(42);

            let buffer = PinnedBuffer::<Felt>::with_capacity(CORE_MAX_TRACE_SIZE as usize);
            let queue = Arc::new(WorkerQueue::new(vec![buffer]));
            let buffer = queue.pop().await.unwrap();
            let (public_values, trace_mle, chip_set, _permit) = full_tracegen(
                &machine,
                program.clone(),
                Arc::new(record),
                &buffer,
                CORE_MAX_TRACE_SIZE as usize,
                LOG_STACKING_HEIGHT,
                CORE_MAX_LOG_ROW_COUNT,
                &scope,
                ProverSemaphore::new(1),
                true,
            )
            .await;

            let chips = machine.smallest_cluster(&chip_set).unwrap();

            let mut cache = BTreeMap::new();
            for chip in chips.iter() {
                let result = codegen_cuda_eval(chip.air.as_ref());
                cache.insert(chip.name().to_string(), result);
            }

            let trace_mle = Arc::new(trace_mle);

            let mut challenger = TestGC::default_challenger();
            challenger.observe(Felt::from_canonical_u32(0x2013));
            challenger.observe(Felt::from_canonical_u32(0x2015));
            challenger.observe(Felt::from_canonical_u32(0x2016));
            challenger.observe(Felt::from_canonical_u32(0x2023));
            challenger.observe(Felt::from_canonical_u32(0x2024));
            let _lambda: Ext = challenger.sample();

            let mut challenger_prover = challenger.clone();
            let batching_challenge = challenger_prover.sample_ext_element();
            let gkr_opening_batch_randomness = challenger_prover.sample_ext_element();
            let max_log_row_count = CORE_MAX_LOG_ROW_COUNT;

            let zeta = Point::<Ext>::rand(&mut rng, CORE_MAX_LOG_ROW_COUNT);
            let individual_column_evals = evaluate_jagged_columns(&trace_mle, zeta.clone());

            let mut preprocessed_ptr: usize = 0;
            let mut main_ptr = chips.iter().map(|x| x.preprocessed_width()).sum::<usize>() + 1;

            let mut chip_openings: BTreeMap<String, ChipEvaluation<Ext>> = BTreeMap::new();
            for chip in chips.iter() {
                let preprocessed_width = chip.preprocessed_width();
                let main_width = chip.width();

                let chip_eval = ChipEvaluation {
                    preprocessed_trace_evaluations: match preprocessed_width {
                        0 => None,
                        _ => Some(MleEval::new(Tensor::from(
                            individual_column_evals
                                [preprocessed_ptr..preprocessed_ptr + preprocessed_width]
                                .to_vec(),
                        ))),
                    },
                    main_trace_evaluations: MleEval::new(Tensor::from(
                        individual_column_evals[main_ptr..main_ptr + main_width].to_vec(),
                    )),
                };

                chip_openings.insert(chip.air.name().to_string(), chip_eval);
                preprocessed_ptr += preprocessed_width;
                main_ptr += main_width;
            }

            let logup_evaluations = LogUpEvaluations { point: zeta, chip_openings };

            let mut group = c.benchmark_group("zerocheck");
            group.sample_size(10);
            group.bench_function("fibonacci", |b| {
                b.iter_batched(
                    || {
                        let pv = public_values.clone();
                        let chal = challenger_prover.clone();
                        // Drain pending GPU work before the timer starts.
                        scope.synchronize_blocking().unwrap();
                        (pv, chal)
                    },
                    |(pv, mut chal)| {
                        let result = zerocheck(
                            chips,
                            &cache,
                            trace_mle.as_ref(),
                            batching_challenge,
                            gkr_opening_batch_randomness,
                            &logup_evaluations,
                            pv,
                            &mut chal,
                            max_log_row_count,
                        );
                        // Wait for any GPU work left enqueued before stopping the timer.
                        scope.synchronize_blocking().unwrap();
                        black_box(result)
                    },
                    BatchSize::PerIteration,
                );
            });
            group.finish();
        })
        .await;
    });
}

criterion_group!(benches, bench_zerocheck);
criterion_main!(benches);
