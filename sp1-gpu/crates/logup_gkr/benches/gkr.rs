//! Bench logup-GKR populate + prove. Two named bench groups in this file:
//!
//! - `populate_circuit` times [`generate_gkr_circuit`] (build the layer stack from the trace).
//! - `prove`            times [`prove_gkr_circuit`]    (sumcheck-per-layer + Fiat-Shamir).
//!
//! Both run off the same [`FullKind`] trace source, so the cluster's chips, per-chip
//! interactions, and jagged trace MLE all come from `with_trace_source`. See
//! [`benches/README.md`] for CLI invocations and the source-arg story.
//!
//! Why two bench groups: GKR layers are halved on each transition, so total work is roughly
//! `first_layer + first_layer/2 + first_layer/4 + ... ≈ 2*first_layer` — splitting the bench
//! lets a regression land on the right side (kernel work vs. the per-round CPU/Fiat-Shamir
//! loop) instead of being hidden in a combined number.

use std::collections::BTreeMap;
use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use slop_challenger::{FieldChallenger, IopCtx};
use slop_multilinear::Point;
use sp1_core_machine::riscv::RiscvAir;
use sp1_gpu_cudart::TaskScope;
use sp1_gpu_jagged_tracegen::test_utils::bench_utils::{
    with_trace_source, FullKind, RealTraceData,
};
use sp1_gpu_jagged_tracegen::test_utils::tracegen_setup::CORE_MAX_LOG_ROW_COUNT;
use sp1_gpu_logup_gkr::{generate_gkr_circuit, prove_logup_gkr, CudaLogUpGkrOptions, Interactions};
use sp1_gpu_utils::{Ext, Felt, TestGC};
use sp1_hypercube::air::MachineAir;
use sp1_hypercube::Chip;
use sp1_primitives::SP1GlobalContext;

/// `prove_gkr_circuit` flag: when true, the prover recomputes the first layer on demand from
/// the raw trace each time it walks back to the leaves; when false, it caches the materialized
/// layer. The end-to-end prover (`prove_logup_gkr`) sets this to true in the existing test, so
/// we match that here for parity. Flip if you want to bench the cache-on path.
const RECOMPUTE_FIRST_LAYER: bool = true;

/// Build the per-chip [`Interactions`] map once per bench setup. Mirrors the loop at the top of
/// `prove_logup_gkr` (`sp1_gpu_logup_gkr::lib::prove_logup_gkr`, lines ~583-588).
fn build_interactions(
    cluster: &std::collections::BTreeSet<Chip<Felt, RiscvAir<Felt>>>,
    scope: &TaskScope,
) -> BTreeMap<String, Arc<Interactions<Felt, TaskScope>>> {
    let mut map = BTreeMap::new();
    for chip in cluster.iter() {
        let interactions = Interactions::new(chip.sends(), chip.receives());
        let device = interactions.copy_to_device(scope).unwrap();
        map.insert(chip.name().to_string(), Arc::new(device));
    }
    map
}

/// `beta_seed` dimension that `prove_logup_gkr` derives from the cluster's max interaction
/// arity. Pulled out so both benches use exactly the same value.
fn beta_seed_dim(cluster: &std::collections::BTreeSet<Chip<Felt, RiscvAir<Felt>>>) -> u32 {
    let max_arity = cluster
        .iter()
        .flat_map(|c| c.sends().iter().chain(c.receives().iter()))
        .map(|i| i.values.len() + 1)
        .max()
        .expect("cluster has no interactions — empty cluster?");
    (max_arity as u32).next_power_of_two().ilog2()
}

const GKR_OPTIONS: CudaLogUpGkrOptions = CudaLogUpGkrOptions {
    recompute_first_layer: RECOMPUTE_FIRST_LAYER,
    num_row_variables: CORE_MAX_LOG_ROW_COUNT,
};

fn run_populate_circuit<R: Rng>(
    c: &mut Criterion,
    id: BenchmarkId,
    scope: &TaskScope,
    _rng: &mut R,
    data: RealTraceData,
) {
    let RealTraceData { machine: _, cluster, public_values: _, device_mle } = data;
    let interactions = build_interactions(&cluster, scope);
    let beta_dim = beta_seed_dim(&cluster);

    let mut group = c.benchmark_group("populate_circuit");
    group.sample_size(10);
    group.bench_with_input(id, &(), |b, _| {
        b.iter_batched(
            || {
                // Per-iteration: a fresh challenger sample for (alpha, beta_seed). Cheap on
                // CPU; doing it here keeps any per-call randomness state out of the timed
                // block. We don't observe the prior trace state — for timing purposes the
                // challenger's history is irrelevant, only its sampling cost is.
                let mut challenger = TestGC::default_challenger();
                let alpha: Ext = challenger.sample_ext_element();
                let beta_seed: Point<Ext> =
                    (0..beta_dim).map(|_| challenger.sample_ext_element::<Ext>()).collect();
                scope.synchronize_blocking().unwrap();
                (alpha, beta_seed)
            },
            |(alpha, beta_seed)| {
                let result = generate_gkr_circuit(
                    &cluster,
                    interactions.clone(),
                    &device_mle,
                    alpha,
                    beta_seed,
                    GKR_OPTIONS,
                    scope.clone(),
                );
                scope.synchronize_blocking().unwrap();
                black_box(result)
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

fn run_prove<R: Rng>(
    c: &mut Criterion,
    id: BenchmarkId,
    scope: &TaskScope,
    _rng: &mut R,
    data: RealTraceData,
) {
    let RealTraceData { machine: _, cluster, public_values: _, device_mle } = data;
    let interactions = build_interactions(&cluster, scope);

    let mut group = c.benchmark_group("prove");
    group.sample_size(10);
    group.bench_with_input(id, &(), |b, _| {
        b.iter_batched(
            || {
                let challenger = TestGC::default_challenger();
                scope.synchronize_blocking().unwrap();
                (interactions.clone(), challenger)
            },
            |(interactions, mut challenger)| {
                let result = prove_logup_gkr::<SP1GlobalContext, _>(
                    &cluster,
                    interactions,
                    &device_mle,
                    GKR_OPTIONS,
                    &mut challenger,
                );
                scope.synchronize_blocking().unwrap();
                black_box(result)
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

fn bench_populate_circuit(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(42);
    with_trace_source(
        c,
        &mut rng,
        FullKind,
        CORE_MAX_LOG_ROW_COUNT,
        |c, id, scope, rng, data| {
            run_populate_circuit(c, id, scope, rng, data);
        },
    );
}

fn bench_prove(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(42);
    with_trace_source(
        c,
        &mut rng,
        FullKind,
        CORE_MAX_LOG_ROW_COUNT,
        |c, id, scope, rng, data| {
            run_prove(c, id, scope, rng, data);
        },
    );
}

criterion_group!(benches, bench_populate_circuit, bench_prove);
criterion_main!(benches);
