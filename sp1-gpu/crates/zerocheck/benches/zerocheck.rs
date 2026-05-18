//! Bench `zerocheck`. The zerocheck *prover* runs on any trace data — only verification cares
//! about constraint satisfaction — so source selection (random / JSON / real) goes through
//! [`with_trace_source`] with [`FullKind`]. For random and JSON sources the helper synthesizes
//! `cluster` (default: the machine's `core` cluster; override with `random:N,cluster=all-chips`)
//! and a zero-filled `public_values` of the right length. See [`benches/README.md`] for details.

use std::collections::BTreeMap;
use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use slop_air::BaseAir;
use slop_algebra::AbstractField;
use slop_challenger::{CanObserve, CanSample, FieldChallenger, IopCtx};
use slop_multilinear::{MleEval, Point};
use slop_tensor::Tensor;
use sp1_gpu_air::codegen_cuda_eval;
use sp1_gpu_cudart::TaskScope;
use sp1_gpu_jagged_tracegen::test_utils::bench_utils::{
    with_trace_source, FullKind, RealTraceData,
};
use sp1_gpu_jagged_tracegen::test_utils::tracegen_setup::CORE_MAX_LOG_ROW_COUNT;
use sp1_gpu_utils::{Ext, Felt, TestGC};
use sp1_gpu_zerocheck::primitives::evaluate_jagged_columns;
use sp1_gpu_zerocheck::zerocheck;
use sp1_hypercube::air::MachineAir;
use sp1_hypercube::{ChipEvaluation, LogUpEvaluations};

fn run_zerocheck<R: Rng>(
    c: &mut Criterion,
    id: BenchmarkId,
    scope: &TaskScope,
    rng: &mut R,
    data: RealTraceData,
) {
    let RealTraceData { machine: _, cluster, public_values, device_mle } = data;
    let chips = &cluster;

    let mut cache = BTreeMap::new();
    for chip in chips.iter() {
        let result = codegen_cuda_eval(chip.air.as_ref());
        cache.insert(chip.name().to_string(), result);
    }

    let trace_mle = Arc::new(device_mle);

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

    let zeta = Point::<Ext>::rand(rng, CORE_MAX_LOG_ROW_COUNT);
    let individual_column_evals = evaluate_jagged_columns(trace_mle.as_ref(), zeta.clone());

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
    // note that setup doesn't reset the challenger so later proofs will not verify
    group.bench_with_input(id, &(), |b, _| {
        b.iter_batched(
            || {
                let pv = public_values.clone();
                scope.synchronize_blocking().unwrap();
                pv
            },
            |pv| {
                let result = zerocheck(
                    chips,
                    &cache,
                    trace_mle.as_ref(),
                    batching_challenge,
                    gkr_opening_batch_randomness,
                    &logup_evaluations,
                    pv,
                    &mut challenger,
                    max_log_row_count,
                );
                scope.synchronize_blocking().unwrap();
                black_box(result)
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

fn bench_zerocheck(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(42);
    with_trace_source(
        c,
        &mut rng,
        FullKind,
        CORE_MAX_LOG_ROW_COUNT,
        |c, id, scope, rng, data| {
            run_zerocheck(c, id, scope, rng, data);
        },
    );
}

criterion_group!(benches, bench_zerocheck);
criterion_main!(benches);
