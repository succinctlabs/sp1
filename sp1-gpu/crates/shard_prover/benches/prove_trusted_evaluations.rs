//! Bench `CudaShardProver::prove_trusted_evaluations`.
//!
//! Setup mirrors the `test_prove_trusted_evaluations` test inside the crate, but uses public APIs
//! only: traces are committed via `sp1_gpu_commit::commit_multilinears`, and the prove call goes
//! through the public `CudaShardProver::prove_trusted_evaluations` delegator.
//!
//! Per-iteration inputs (`eval_point`, evaluation claims, `prover_data`, challenger) are built up
//! in Criterion's `iter_batched` setup so the timed routine contains nothing but the prove call.

use std::collections::BTreeMap;
use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use slop_basefold::BasefoldVerifier;
use slop_challenger::IopCtx;
use slop_commit::Rounds;
use slop_futures::queue::WorkerQueue;
use slop_multilinear::{MleEval, MultilinearPcsChallenger};
use sp1_core_machine::io::SP1Stdin;
use sp1_core_machine::riscv::RiscvAir;
use sp1_gpu_air::codegen_cuda_eval;
use sp1_gpu_basefold::FriCudaProver;
use sp1_gpu_commit::commit_multilinears;
use sp1_gpu_cudart::{run_in_place, run_sync_in_place, DeviceTensor, PinnedBuffer, TaskScope};
use sp1_gpu_jagged_tracegen::test_utils::tracegen_setup::{
    self, CORE_MAX_LOG_ROW_COUNT, LOG_STACKING_HEIGHT,
};
use sp1_gpu_jagged_tracegen::{full_tracegen, CORE_MAX_TRACE_SIZE};
use sp1_gpu_logup_gkr::Interactions;
use sp1_gpu_merkle_tree::{CudaTcsProver, Poseidon2SP1Field16CudaProver};
use sp1_gpu_shard_prover::{CudaShardProver, CudaShardProverComponents};
use sp1_gpu_utils::test_utils::random::random_jagged_trace_mle;
use sp1_gpu_utils::{Ext, Felt, TestGC};
use sp1_gpu_zerocheck::primitives::round_batch_evaluations;
use sp1_hypercube::air::MachineAir;
use sp1_hypercube::prover::ProverSemaphore;
use sp1_hypercube::SP1InnerPcs;
use sp1_primitives::fri_params::core_fri_config;

pub struct BenchProverComponents {}

impl CudaShardProverComponents<TestGC> for BenchProverComponents {
    type P = Poseidon2SP1Field16CudaProver;
    type Air = RiscvAir<Felt>;
    type C = SP1InnerPcs;
    type DeviceChallenger = sp1_gpu_challenger::DuplexChallenger<Felt, TaskScope>;
}

fn bench_prove_trusted_evaluations(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (machine, record, program) =
            tracegen_setup::setup(&test_artifacts::FIBONACCI_ELF, SP1Stdin::new()).await;

        run_in_place(|scope| async move {
            let buffer = PinnedBuffer::<Felt>::with_capacity(CORE_MAX_TRACE_SIZE as usize);
            let queue = Arc::new(WorkerQueue::new(vec![buffer]));
            let buffer = queue.pop().await.unwrap();
            let (_public_values, jagged_trace_data, _shard_chips, _permit) = full_tracegen(
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
            let jagged_trace_data = Arc::new(jagged_trace_data);

            let verifier = BasefoldVerifier::<TestGC>::new(core_fri_config(), 2);
            let basefold_prover = FriCudaProver::<TestGC, _, Felt>::new(
                Poseidon2SP1Field16CudaProver::new(&scope),
                verifier.fri_config,
                LOG_STACKING_HEIGHT,
            );

            let (_preprocessed_digest, preprocessed_prover_data) =
                commit_multilinears::<TestGC, _>(
                    &jagged_trace_data,
                    CORE_MAX_LOG_ROW_COUNT,
                    true,
                    false,
                    &basefold_prover,
                )
                .unwrap();

            let (_main_digest, main_prover_data) = commit_multilinears::<TestGC, _>(
                &jagged_trace_data,
                CORE_MAX_LOG_ROW_COUNT,
                false,
                false,
                &basefold_prover,
            )
            .unwrap();

            let mut all_interactions = BTreeMap::new();
            for chip in machine.chips().iter() {
                let host_interactions = Interactions::new(chip.sends(), chip.receives());
                let device_interactions = host_interactions.copy_to_device(&scope).unwrap();
                all_interactions.insert(chip.name().to_string(), Arc::new(device_interactions));
            }

            let mut all_zerocheck_programs = BTreeMap::new();
            for chip in machine.chips().iter() {
                let result = codegen_cuda_eval(chip.air.as_ref());
                all_zerocheck_programs.insert(chip.name().to_string(), result);
            }

            let trace_buffers =
                Arc::new(WorkerQueue::new(vec![PinnedBuffer::<Felt>::with_capacity(
                    CORE_MAX_TRACE_SIZE as usize,
                )]));

            let shard_prover = CudaShardProver::<TestGC, BenchProverComponents>::new(
                trace_buffers,
                CORE_MAX_LOG_ROW_COUNT,
                basefold_prover,
                machine,
                CORE_MAX_TRACE_SIZE as usize,
                scope.clone(),
                all_interactions,
                all_zerocheck_programs,
                false,
                false,
            );

            let mut challenger = TestGC::default_challenger();
            let eval_point = challenger.sample_point(CORE_MAX_LOG_ROW_COUNT);
            let evaluation_claims =
                round_batch_evaluations(&eval_point, jagged_trace_data.as_ref());

            let mut group = c.benchmark_group("prove_trusted_evaluations");
            group.sample_size(10);
            group.bench_function("fibonacci", |b| {
                b.iter_batched(
                    || {
                        let mut new_evaluation_claims = Vec::new();
                        for round_evals in evaluation_claims.iter() {
                            let mut round_host: Vec<Ext> = Vec::new();
                            for eval in round_evals.iter() {
                                round_host.extend_from_slice(eval.to_vec().as_slice());
                            }
                            let device_tensor = DeviceTensor::from_host(
                                &MleEval::from(round_host).into_evaluations(),
                                &scope,
                            )
                            .unwrap();
                            new_evaluation_claims.push(MleEval::new(device_tensor.into_inner()));
                        }
                        let claims: Rounds<_> = new_evaluation_claims.into_iter().collect();
                        let prover_data =
                            Rounds::from_iter([&preprocessed_prover_data, &main_prover_data]);
                        // Drain pending H2D copies before the timer starts.
                        scope.synchronize_blocking().unwrap();
                        (eval_point.clone(), claims, prover_data, challenger.clone())
                    },
                    |(pt, claims, prover_data, mut chal)| {
                        let proof = shard_prover
                            .prove_trusted_evaluations(
                                pt,
                                claims,
                                jagged_trace_data.as_ref(),
                                prover_data,
                                &mut chal,
                            )
                            .unwrap();
                        // Wait for any GPU work the prove call left enqueued before stopping the timer.
                        scope.synchronize_blocking().unwrap();
                        black_box(proof)
                    },
                    BatchSize::PerIteration,
                );
            });
            group.finish();
        })
        .await;
    });
}

/// Same prove call but with a synthetic random trace (no real ELF / tracegen). Useful for
/// measuring the prover under controlled trace sizes — `TOTAL_AREA` directly governs the input
/// size, no Fibonacci-shaped variation across runs.
fn bench_prove_trusted_evaluations_random(c: &mut Criterion) {
    const TOTAL_AREA: u64 = 1 << 25;

    run_sync_in_place(|scope| {
        let mut rng = StdRng::seed_from_u64(42);

        let machine = RiscvAir::<Felt>::machine();
        let chips = machine.chips();

        let host_mle =
            random_jagged_trace_mle::<Felt, _, _>(&mut rng, chips, TOTAL_AREA, LOG_STACKING_HEIGHT);
        let jagged_trace_data = Arc::new(host_mle.into_device(&scope));

        let verifier = BasefoldVerifier::<TestGC>::new(core_fri_config(), 2);
        let basefold_prover = FriCudaProver::<TestGC, _, Felt>::new(
            Poseidon2SP1Field16CudaProver::new(&scope),
            verifier.fri_config,
            LOG_STACKING_HEIGHT,
        );

        let (_preprocessed_digest, preprocessed_prover_data) = commit_multilinears::<TestGC, _>(
            &jagged_trace_data,
            CORE_MAX_LOG_ROW_COUNT,
            true,
            false,
            &basefold_prover,
        )
        .unwrap();

        let (_main_digest, main_prover_data) = commit_multilinears::<TestGC, _>(
            &jagged_trace_data,
            CORE_MAX_LOG_ROW_COUNT,
            false,
            false,
            &basefold_prover,
        )
        .unwrap();

        let mut all_interactions = BTreeMap::new();
        for chip in machine.chips().iter() {
            let host_interactions = Interactions::new(chip.sends(), chip.receives());
            let device_interactions = host_interactions.copy_to_device(&scope).unwrap();
            all_interactions.insert(chip.name().to_string(), Arc::new(device_interactions));
        }

        let mut all_zerocheck_programs = BTreeMap::new();
        for chip in machine.chips().iter() {
            let result = codegen_cuda_eval(chip.air.as_ref());
            all_zerocheck_programs.insert(chip.name().to_string(), result);
        }

        let trace_buffers = Arc::new(WorkerQueue::new(vec![PinnedBuffer::<Felt>::with_capacity(
            CORE_MAX_TRACE_SIZE as usize,
        )]));

        let shard_prover = CudaShardProver::<TestGC, BenchProverComponents>::new(
            trace_buffers,
            CORE_MAX_LOG_ROW_COUNT,
            basefold_prover,
            machine,
            CORE_MAX_TRACE_SIZE as usize,
            scope.clone(),
            all_interactions,
            all_zerocheck_programs,
            false,
            false,
        );

        let mut challenger = TestGC::default_challenger();
        let eval_point = challenger.sample_point(CORE_MAX_LOG_ROW_COUNT);
        let evaluation_claims = round_batch_evaluations(&eval_point, jagged_trace_data.as_ref());

        let mut group = c.benchmark_group("prove_trusted_evaluations");
        group.sample_size(10);
        group.bench_function("random_total_area_2^25", |b| {
            b.iter_batched(
                || {
                    let mut new_evaluation_claims = Vec::new();
                    for round_evals in evaluation_claims.iter() {
                        let mut round_host: Vec<Ext> = Vec::new();
                        for eval in round_evals.iter() {
                            round_host.extend_from_slice(eval.to_vec().as_slice());
                        }
                        let device_tensor = DeviceTensor::from_host(
                            &MleEval::from(round_host).into_evaluations(),
                            &scope,
                        )
                        .unwrap();
                        new_evaluation_claims.push(MleEval::new(device_tensor.into_inner()));
                    }
                    let claims: Rounds<_> = new_evaluation_claims.into_iter().collect();
                    let prover_data =
                        Rounds::from_iter([&preprocessed_prover_data, &main_prover_data]);
                    scope.synchronize_blocking().unwrap();
                    (eval_point.clone(), claims, prover_data, challenger.clone())
                },
                |(pt, claims, prover_data, mut chal)| {
                    let proof = shard_prover
                        .prove_trusted_evaluations(
                            pt,
                            claims,
                            jagged_trace_data.as_ref(),
                            prover_data,
                            &mut chal,
                        )
                        .unwrap();
                    scope.synchronize_blocking().unwrap();
                    black_box(proof)
                },
                BatchSize::PerIteration,
            );
        });
        group.finish();
    })
    .unwrap();
}

criterion_group!(benches, bench_prove_trusted_evaluations, bench_prove_trusted_evaluations_random);
criterion_main!(benches);
