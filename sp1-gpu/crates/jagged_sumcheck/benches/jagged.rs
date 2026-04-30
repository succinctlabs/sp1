use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use slop_algebra::AbstractField;
use slop_challenger::IopCtx;
use slop_multilinear::Point;
use sp1_core_machine::riscv::RiscvAir;
use sp1_gpu_cudart::{run_sync_in_place, DevicePoint};
use sp1_gpu_jagged_sumcheck::{generate_jagged_sumcheck_poly, jagged_sumcheck};
use sp1_gpu_jagged_tracegen::test_utils::tracegen_setup::{
    CORE_MAX_LOG_ROW_COUNT, LOG_STACKING_HEIGHT,
};
use sp1_gpu_utils::config::{Ext, Felt, TestGC};
use sp1_gpu_utils::test_utils::random::random_jagged_trace_mle;

fn bench_jagged_sumcheck(c: &mut Criterion) {
    const TOTAL_AREA: u64 = 1 << 25;

    run_sync_in_place(|scope| {
        let mut rng = StdRng::seed_from_u64(42);

        let machine = RiscvAir::<Felt>::machine();
        let chips = machine.chips();

        let host_mle =
            random_jagged_trace_mle::<Felt, _, _>(&mut rng, chips, TOTAL_AREA, LOG_STACKING_HEIGHT);
        let device_mle = host_mle.into_device(&scope);

        // The jagged sumcheck operates over `column_heights.len()` logical columns.
        let log_col_count = device_mle.column_heights.len().next_power_of_two().ilog2();

        let z_row_host = Point::<Ext>::rand(&mut rng, CORE_MAX_LOG_ROW_COUNT);
        let z_col_host = Point::<Ext>::rand(&mut rng, log_col_count);
        let z_row_device = DevicePoint::from_host(&z_row_host, &scope).unwrap().into_inner();
        let z_col_device = DevicePoint::from_host(&z_col_host, &scope).unwrap().into_inner();

        // Correctness isn't tested here; an arbitrary claim is fine.
        let claim = Ext::zero();

        let mut group = c.benchmark_group("jagged_sumcheck");
        group.sample_size(10);
        group.bench_function("total_area_2^25", |b| {
            b.iter_batched(
                || {
                    let eq_z_row = DevicePoint::new(z_row_device.clone()).partial_lagrange();
                    let eq_z_col = DevicePoint::new(z_col_device.clone()).partial_lagrange();
                    let challenger = TestGC::default_challenger();
                    // Drain pending GPU work before the timer starts.
                    scope.synchronize_blocking().unwrap();
                    (eq_z_row, eq_z_col, challenger)
                },
                |(eq_z_row, eq_z_col, mut challenger)| {
                    let poly = generate_jagged_sumcheck_poly(&device_mle, eq_z_col, eq_z_row);
                    let result = jagged_sumcheck(poly, &mut challenger, claim);
                    // Wait for any GPU work left enqueued before stopping the timer.
                    scope.synchronize_blocking().unwrap();
                    black_box(result)
                },
                BatchSize::PerIteration,
            );
        });
        group.finish();
    })
    .unwrap();
}

criterion_group!(benches, bench_jagged_sumcheck);
criterion_main!(benches);
