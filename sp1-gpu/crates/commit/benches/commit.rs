use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use slop_challenger::IopCtx;
use slop_jagged::JaggedPcsVerifier;
use sp1_core_machine::riscv::RiscvAir;
use sp1_gpu_basefold::FriCudaProver;
use sp1_gpu_commit::commit_multilinears;
use sp1_gpu_cudart::run_sync_in_place;
use sp1_gpu_jagged_tracegen::test_utils::tracegen_setup::{
    CORE_MAX_LOG_ROW_COUNT, LOG_STACKING_HEIGHT,
};
use sp1_gpu_merkle_tree::{CudaTcsProver, Poseidon2SP1Field16CudaProver};
use sp1_gpu_utils::config::{Felt, TestGC};
use sp1_gpu_utils::test_utils::random::random_jagged_trace_mle;
use sp1_hypercube::SP1InnerPcs;
use sp1_primitives::fri_params::core_fri_config;

fn bench_commit(c: &mut Criterion) {
    const TOTAL_AREA: u64 = 1 << 25;
    const NUM_ROUNDS: usize = 2;

    type JC = SP1InnerPcs;

    run_sync_in_place(|scope| {
        let mut rng = StdRng::seed_from_u64(42);

        let machine = RiscvAir::<Felt>::machine();
        let chips = machine.chips();

        let host_mle =
            random_jagged_trace_mle::<Felt, _, _>(&mut rng, chips, TOTAL_AREA, LOG_STACKING_HEIGHT);
        let device_mle = host_mle.into_device(&scope);

        let jagged_verifier = JaggedPcsVerifier::<_, JC>::new_from_basefold_params(
            core_fri_config(),
            LOG_STACKING_HEIGHT,
            CORE_MAX_LOG_ROW_COUNT as usize,
            NUM_ROUNDS,
        );

        let tcs_prover = Poseidon2SP1Field16CudaProver::new(&scope);
        let basefold_prover = FriCudaProver::<TestGC, _, <TestGC as IopCtx>::F>::new(
            tcs_prover,
            jagged_verifier.pcs_verifier.basefold_verifier.fri_config,
            LOG_STACKING_HEIGHT,
        );

        let mut group = c.benchmark_group("commit_multilinears");
        group.sample_size(10);
        group.bench_function("main_total_area_2^25", |b| {
            b.iter(|| {
                black_box(
                    commit_multilinears::<TestGC, _>(
                        &device_mle,
                        CORE_MAX_LOG_ROW_COUNT,
                        false, // use_preprocessed
                        false, // drop_main_traces
                        &basefold_prover,
                    )
                    .unwrap(),
                )
            });
        });
        group.finish();
    })
    .unwrap();
}

criterion_group!(benches, bench_commit);
criterion_main!(benches);
