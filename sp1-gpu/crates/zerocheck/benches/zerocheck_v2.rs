//! Bench `zerocheck_v2` — the DAG-native lowering path. Mirrors
//! `benches/zerocheck.rs` exactly so the two harnesses are directly
//! comparable side-by-side.

use std::collections::BTreeMap;
use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use slop_air::BaseAir;
use slop_algebra::AbstractField;
use slop_challenger::{CanObserve, CanSample, FieldChallenger, IopCtx};
use slop_multilinear::{MleEval, Point};
use slop_tensor::Tensor;
use sp1_gpu_air::v2::ChunkBudget;
use sp1_gpu_cudart::TaskScope;
use sp1_gpu_jagged_tracegen::test_utils::bench_utils::{
    with_trace_source, FullKind, RealTraceData,
};
use sp1_gpu_utils::{Ext, Felt, TestGC};
use sp1_gpu_zerocheck::primitives::evaluate_jagged_columns;
use sp1_gpu_zerocheck::v2::{upload_machine_bytecode, zerocheck_v2};
use sp1_hypercube::air::MachineAir;
use sp1_hypercube::log2_ceil_usize;
use sp1_hypercube::{ChipEvaluation, LogUpEvaluations};

fn run_zerocheck_v2<R: Rng>(
    c: &mut Criterion,
    id: BenchmarkId,
    scope: &TaskScope,
    rng: &mut R,
    data: RealTraceData,
) {
    let RealTraceData { machine: _, cluster, public_values, device_mle } = data;
    let chips = &cluster;

    // Compile + upload the machine's v2 bytecode once.
    let machine_bytecode =
        Arc::new(upload_machine_bytecode(chips, ChunkBudget::default_v1(), scope));

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
    // Derive max_log_row_count from the actual chip heights. The bench's old
    // `CORE_MAX_LOG_ROW_COUNT = 22` only covers `core_2^25`-sized random
    // traces — bigger areas can put more than 2^22 rows in a single chip and
    // trip `VirtualGeq::new`'s assert.
    let max_chip_height =
        trace_mle.dense_data.main_table_index.values().map(|o| o.poly_size).max().unwrap_or(1);
    let max_log_row_count = log2_ceil_usize(max_chip_height).max(1);

    let zeta = Point::<Ext>::rand(rng, max_log_row_count as u32);
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

    let mut group = c.benchmark_group("zerocheck_v2");
    // note that setup doesn't reset the challenger so later proofs will not verify
    group.bench_with_input(id, &(), |b, _| {
        b.iter_batched(
            || {
                let pv = public_values.clone();
                scope.synchronize_blocking().unwrap();
                pv
            },
            |pv| {
                let result = zerocheck_v2(
                    chips,
                    &machine_bytecode,
                    trace_mle.as_ref(),
                    batching_challenge,
                    gkr_opening_batch_randomness,
                    &logup_evaluations,
                    pv,
                    &mut challenger,
                    max_log_row_count as u32,
                );
                scope.synchronize_blocking().unwrap();
                black_box(result)
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

fn bench_zerocheck_v2(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(42);
    with_trace_source(c, &mut rng, FullKind, |c, id, scope, rng, data| {
        run_zerocheck_v2(c, id, scope, rng, data);
    });
}

criterion_group!(benches, bench_zerocheck_v2);
criterion_main!(benches);
