//! Bench `JaggedPcsVerifier::verify_trusted_evaluations` on a proof produced
//! by the GPU `CudaShardProver::prove_trusted_evaluations` path.
//!
//! Setup builds a proof once (with the prover's starting challenger state
//! saved); the timed routine just clones that starting state and calls
//! `verify_trusted_evaluations`.
//!
//! Set `DEBUG=1` (or `DEBUG=true`) when running this bench so the
//! `slop-jagged` verifier executes the optional O(K · 2^c) bit-MLE check
//! that would otherwise be delegated to the PCS in production — that's the
//! realistic upper-bound the comparison against main is measuring.

use std::collections::BTreeMap;
use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use slop_basefold::BasefoldVerifier;
use slop_challenger::IopCtx;
use slop_commit::Rounds;
use slop_futures::queue::WorkerQueue;
use slop_jagged::JaggedPcsVerifier;
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
use sp1_hypercube::{SP1InnerPcs, NUM_SP1_COMMITMENTS};
use sp1_primitives::fri_params::core_fri_config;

pub struct BenchProverComponents {}

impl CudaShardProverComponents<TestGC> for BenchProverComponents {
    type P = Poseidon2SP1Field16CudaProver;
    type Air = RiscvAir<Felt>;
    type C = SP1InnerPcs;
    type DeviceChallenger = sp1_gpu_challenger::DuplexChallenger<Felt, TaskScope>;
}

fn run_verify_trusted_evaluations<R: Rng>(
    c: &mut Criterion,
    id: BenchmarkId,
    scope: &TaskScope,
    _rng: &mut R,
    device_mle: &JaggedTraceMle<Felt, TaskScope>,
) {
    let jagged_trace_data = device_mle;

    let verifier = BasefoldVerifier::<TestGC>::new(core_fri_config(), 2, LOG_STACKING_HEIGHT);
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

    // Build host- and device-side evaluation claims.  Sample the eval point
    // first so we can save the prover's starting challenger state for the
    // verifier (the GPU prove path doesn't observe commitments — it just
    // samples z_col from the incoming challenger — so the verifier must use
    // an identical starting state for FS to line up).
    let mut prover_challenger = TestGC::default_challenger();
    let eval_point = prover_challenger.sample_point(CORE_MAX_LOG_ROW_COUNT);
    let evaluation_claims = round_batch_evaluations(&eval_point, jagged_trace_data);

    // Host-side claims for the verifier (one MleEval per round, flattened
    // across that round's chips).
    let evaluation_claims_host: Vec<MleEval<Ext>> = evaluation_claims
        .iter()
        .map(|round_evals| {
            let mut round_host: Vec<Ext> = Vec::new();
            for eval in round_evals.iter() {
                round_host.extend_from_slice(eval.to_vec().as_slice());
            }
            MleEval::from(round_host)
        })
        .collect();

    // Device-side claims for the prover (same layout but resident on GPU).
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

    // Snapshot the challenger state the verifier must replicate.
    let verifier_starting_challenger = prover_challenger.clone();

    // Generate the proof once (outside the timing loop).
    let proof = shard_prover
        .prove_trusted_evaluations(
            eval_point.clone(),
            claims.clone(),
            jagged_trace_data,
            prover_data,
            &mut prover_challenger,
        )
        .unwrap();
    scope.synchronize_blocking().unwrap();

    // Construct the CPU verifier with the same parameters as the prover.
    let jagged_verifier = JaggedPcsVerifier::<TestGC, SP1InnerPcs>::new_from_basefold_params(
        core_fri_config(),
        LOG_STACKING_HEIGHT,
        CORE_MAX_LOG_ROW_COUNT as usize,
        NUM_SP1_COMMITMENTS,
    );

    let commitments = [_preprocessed_digest, _main_digest];

    // Sanity check: a proof produced by the GPU prover must verify with the
    // CPU verifier (using a clone of the saved starting challenger state).
    {
        let mut ch = verifier_starting_challenger.clone();
        jagged_verifier
            .verify_trusted_evaluations(
                &commitments,
                eval_point.clone(),
                &evaluation_claims_host,
                &proof,
                &mut ch,
            )
            .expect("setup sanity verify failed");
    }

    let mut group = c.benchmark_group("verify_trusted_evaluations");
    group.bench_with_input(id, &(), |b, _| {
        b.iter_batched(
            || verifier_starting_challenger.clone(),
            |mut ch| {
                jagged_verifier
                    .verify_trusted_evaluations(
                        &commitments,
                        eval_point.clone(),
                        &evaluation_claims_host,
                        &proof,
                        &mut ch,
                    )
                    .expect("verify failed");
                black_box(());
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_verify_trusted_evaluations(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(42);
    with_trace_source(
        c,
        &mut rng,
        JaggedKind,
        CORE_MAX_LOG_ROW_COUNT,
        |c, id, scope, rng, device_mle| {
            run_verify_trusted_evaluations(c, id, scope, rng, &device_mle);
        },
    );
}

criterion_group!(benches, bench_verify_trusted_evaluations);
criterion_main!(benches);
