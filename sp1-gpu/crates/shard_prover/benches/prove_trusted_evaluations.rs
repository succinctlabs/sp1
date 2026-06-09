//! Bench `CudaShardProver::prove_trusted_evaluations` against one trace source per invocation.
//!
//! The prove call works on any trace shape (it doesn't care whether the data satisfies AIR
//! constraints), so source selection (random / JSON / real) goes through
//! [`sp1_gpu_jagged_tracegen::test_utils::bench_utils::with_trace_source`].
//!
//! Per-iteration inputs (`eval_point`, evaluation claims, `prover_data`, challenger) are built up
//! in Criterion's `iter_batched` setup so the timed routine contains nothing but the prove call.

use std::collections::BTreeMap;
use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use slop_basefold::BasefoldVerifier;
use slop_challenger::IopCtx;
use slop_commit::Rounds;
use slop_futures::queue::WorkerQueue;
use slop_multilinear::{MleEval, MultilinearPcsChallenger};
use sp1_core_machine::riscv::RiscvAir;
use sp1_gpu_basefold::FriCudaProver;
use sp1_gpu_commit::commit_multilinears;
use sp1_gpu_cudart::{DeviceTensor, PinnedBuffer, TaskScope};
use sp1_gpu_jagged_tracegen::test_utils::bench_utils::{with_trace_source, JaggedKind};
use sp1_gpu_jagged_tracegen::test_utils::tracegen_setup::{
    CORE_MAX_LOG_ROW_COUNT, LOG_STACKING_HEIGHT,
};
use sp1_gpu_jagged_tracegen::CORE_MAX_TRACE_SIZE;
use sp1_gpu_logup_gkr::Interactions;
use sp1_gpu_merkle_tree::{CudaTcsProver, Poseidon2SP1Field16CudaProver};
use sp1_gpu_shard_prover::{CudaShardProver, CudaShardProverComponents};
use sp1_gpu_utils::{Ext, Felt, JaggedTraceMle, TestGC};
use sp1_gpu_zerocheck::primitives::round_batch_evaluations;
use sp1_hypercube::air::MachineAir;
use sp1_hypercube::SP1InnerPcs;
use sp1_primitives::fri_params::core_fri_config;

pub struct BenchProverComponents {}

impl CudaShardProverComponents<TestGC> for BenchProverComponents {
    type P = Poseidon2SP1Field16CudaProver;
    type Air = RiscvAir<Felt>;
    type C = SP1InnerPcs;
    type DeviceChallenger = sp1_gpu_challenger::DuplexChallenger<Felt, TaskScope>;
}

fn run_prove_trusted_evaluations<R: Rng>(
    c: &mut Criterion,
    id: BenchmarkId,
    scope: &TaskScope,
    _rng: &mut R,
    device_mle: &JaggedTraceMle<Felt, TaskScope>,
) {
    let jagged_trace_data = device_mle;

    let verifier = BasefoldVerifier::<TestGC>::new(core_fri_config(), 2);
    let basefold_prover = FriCudaProver::<TestGC, _, Felt>::new(
        Poseidon2SP1Field16CudaProver::new(scope),
        verifier.fri_config,
        LOG_STACKING_HEIGHT,
    );

    let (_preprocessed_digest, preprocessed_prover_data) = commit_multilinears::<TestGC, _>(
        jagged_trace_data,
        CORE_MAX_LOG_ROW_COUNT,
        true,
        false,
        &basefold_prover,
    )
    .unwrap();

    let (_main_digest, main_prover_data) = commit_multilinears::<TestGC, _>(
        jagged_trace_data,
        CORE_MAX_LOG_ROW_COUNT,
        false,
        false,
        &basefold_prover,
    )
    .unwrap();

    let machine = RiscvAir::<Felt>::machine();

    let mut all_interactions = BTreeMap::new();
    for chip in machine.chips().iter() {
        let host_interactions = Interactions::new(chip.sends(), chip.receives());
        let device_interactions = host_interactions.copy_to_device(scope).unwrap();
        all_interactions.insert(chip.name().to_string(), Arc::new(device_interactions));
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
        false,
        false,
    );

    let mut challenger = TestGC::default_challenger();
    let eval_point = challenger.sample_point(CORE_MAX_LOG_ROW_COUNT);
    let evaluation_claims = round_batch_evaluations(&eval_point, jagged_trace_data);

    let mut new_evaluation_claims = Vec::new();
    for round_evals in evaluation_claims.iter() {
        let mut round_host: Vec<Ext> = Vec::new();
        for eval in round_evals.iter() {
            round_host.extend_from_slice(eval.to_vec().as_slice());
        }
        let device_tensor =
            DeviceTensor::from_host(&MleEval::from(round_host).into_evaluations(), scope).unwrap();
        new_evaluation_claims.push(MleEval::new(device_tensor.into_inner()));
    }
    let claims: Rounds<_> = new_evaluation_claims.into_iter().collect();
    let prover_data = Rounds::from_iter([&preprocessed_prover_data, &main_prover_data]);
    scope.synchronize_blocking().unwrap();

    let mut group = c.benchmark_group("prove_trusted_evaluations");
    // note that setup doesn't reset the challenger so later proofs will not verify
    group.bench_with_input(id, &(), |b, _| {
        b.iter_batched(
            || {
                let out = (eval_point.clone(), claims.clone(), prover_data.clone());
                scope.synchronize_blocking().unwrap();
                out
            },
            |(pt, claims, prover_data)| {
                let proof = shard_prover
                    .prove_trusted_evaluations(
                        pt,
                        claims,
                        jagged_trace_data,
                        prover_data,
                        &mut challenger,
                    )
                    .unwrap();
                scope.synchronize_blocking().unwrap();
                black_box(proof)
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

fn bench_prove_trusted_evaluations(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(42);
    with_trace_source(
        c,
        &mut rng,
        JaggedKind,
        CORE_MAX_LOG_ROW_COUNT,
        |c, id, scope, rng, device_mle| {
            run_prove_trusted_evaluations(c, id, scope, rng, &device_mle);
        },
    );
}

criterion_group!(benches, bench_prove_trusted_evaluations);
criterion_main!(benches);
