//! Bench `jagged_sumcheck` against one trace source per invocation: random heights, a JSON
//! layout, or a real zkVM execution. The source is picked from CLI args by
//! [`sp1_gpu_jagged_tracegen::test_utils::bench_utils::with_trace_source`]; see its docs for the
//! supported `--` invocations.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use slop_algebra::AbstractField;
use slop_challenger::IopCtx;
use slop_multilinear::Point;
use sp1_gpu_cudart::{DevicePoint, TaskScope};
use sp1_gpu_jagged_sumcheck::{generate_jagged_sumcheck_poly, jagged_sumcheck};
use sp1_gpu_jagged_tracegen::test_utils::bench_utils::{with_trace_source, JaggedKind};
use sp1_gpu_jagged_tracegen::test_utils::tracegen_setup::{
    CORE_MAX_LOG_ROW_COUNT, LOG_STACKING_HEIGHT,
};
use sp1_gpu_utils::config::{Ext, Felt, TestGC};
use sp1_gpu_utils::JaggedTraceMle;

/// Run the jagged sumcheck timing loop against an already-on-device trace MLE.
fn run_jagged_sumcheck<R: Rng>(
    c: &mut Criterion,
    id: BenchmarkId,
    scope: &TaskScope,
    rng: &mut R,
    device_mle: &JaggedTraceMle<Felt, TaskScope>,
) {
    // The jagged sumcheck operates over `column_heights.len()` logical columns.
    let log_col_count = device_mle.column_heights.len().next_power_of_two().ilog2();

    let z_row_host = Point::<Ext>::rand(rng, CORE_MAX_LOG_ROW_COUNT);
    let z_col_host = Point::<Ext>::rand(rng, log_col_count);
    let z_row_device = DevicePoint::from_host(&z_row_host, scope).unwrap().into_inner();
    let z_col_device = DevicePoint::from_host(&z_col_host, scope).unwrap().into_inner();

    // Correctness isn't tested here; an arbitrary claim is fine.
    let claim = Ext::zero();

    let mut challenger = TestGC::default_challenger();

    let mut group = c.benchmark_group("jagged_sumcheck");
    // note that setup doesn't reset the challenger so later proofs will not verify
    group.bench_with_input(id, &(), |b, _| {
        b.iter_batched(
            || {
                let out = (z_row_device.clone(), z_col_device.clone());
                scope.synchronize_blocking().unwrap();
                out
            },
            |(z_row_device, z_col_device)| {
                let eq_z_row = DevicePoint::new(z_row_device).partial_lagrange();
                let eq_z_col = DevicePoint::new(z_col_device).partial_lagrange();
                let poly = generate_jagged_sumcheck_poly(device_mle, eq_z_col, eq_z_row);
                let result =
                    jagged_sumcheck(poly, &mut challenger, claim, LOG_STACKING_HEIGHT as usize);
                // Wait for any GPU work left enqueued before stopping the timer.
                scope.synchronize_blocking().unwrap();
                black_box(result)
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

fn bench_jagged_sumcheck(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(42);
    with_trace_source(
        c,
        &mut rng,
        JaggedKind,
        CORE_MAX_LOG_ROW_COUNT,
        |c, id, scope, rng, device_mle| {
            run_jagged_sumcheck(c, id, scope, rng, &device_mle);
        },
    );
}

criterion_group!(benches, bench_jagged_sumcheck);
criterion_main!(benches);
