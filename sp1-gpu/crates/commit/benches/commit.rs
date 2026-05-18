//! Bench `sp1_gpu_commit::commit_multilinears` against one trace source per invocation. Source
//! selection (random / JSON / real) is handled by
//! [`sp1_gpu_jagged_tracegen::test_utils::bench_utils::with_trace_source`]; see its docs for the
//! supported `--` invocations.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use slop_challenger::IopCtx;
use slop_jagged::JaggedPcsVerifier;
use sp1_gpu_basefold::FriCudaProver;
use sp1_gpu_commit::commit_multilinears;
use sp1_gpu_cudart::TaskScope;
use sp1_gpu_jagged_tracegen::test_utils::bench_utils::{with_trace_source, JaggedKind};
use sp1_gpu_jagged_tracegen::test_utils::tracegen_setup::{
    CORE_MAX_LOG_ROW_COUNT, LOG_STACKING_HEIGHT,
};
use sp1_gpu_merkle_tree::{CudaTcsProver, Poseidon2SP1Field16CudaProver};
use sp1_gpu_utils::config::{Felt, TestGC};
use sp1_gpu_utils::JaggedTraceMle;
use sp1_hypercube::SP1InnerPcs;
use sp1_primitives::fri_params::core_fri_config;

fn run_commit<R: Rng>(
    c: &mut Criterion,
    id: BenchmarkId,
    scope: &TaskScope,
    _rng: &mut R,
    device_mle: &JaggedTraceMle<Felt, TaskScope>,
) {
    const NUM_ROUNDS: usize = 2;

    let jagged_verifier = JaggedPcsVerifier::<_, SP1InnerPcs>::new_from_basefold_params(
        core_fri_config(),
        LOG_STACKING_HEIGHT,
        CORE_MAX_LOG_ROW_COUNT as usize,
        NUM_ROUNDS,
    );

    let basefold_prover = FriCudaProver::<TestGC, _, <TestGC as IopCtx>::F>::new(
        Poseidon2SP1Field16CudaProver::new(scope),
        jagged_verifier.pcs_verifier.basefold_verifier.fri_config,
        LOG_STACKING_HEIGHT,
    );

    let mut group = c.benchmark_group("commit_multilinears");
    group.bench_with_input(id, &(), |b, _| {
        b.iter(|| {
            let result = commit_multilinears::<TestGC, _>(
                device_mle,
                CORE_MAX_LOG_ROW_COUNT,
                false, // use_preprocessed
                false, // drop_main_traces
                &basefold_prover,
            )
            .unwrap();
            scope.synchronize_blocking().unwrap();
            black_box(result)
        });
    });
    group.finish();
}

fn bench_commit(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(42);
    with_trace_source(
        c,
        &mut rng,
        JaggedKind,
        CORE_MAX_LOG_ROW_COUNT,
        |c, id, scope, rng, device_mle| {
            run_commit(c, id, scope, rng, &device_mle);
        },
    );
}

criterion_group!(benches, bench_commit);
criterion_main!(benches);
