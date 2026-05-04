//! Bench `jagged_sumcheck` with three trace-data sources, registered as siblings under the
//! `jagged_sumcheck` Criterion group:
//!
//! - `random/total_area_2^25`: synthetic trace with random column heights summing to ~`TOTAL_AREA`.
//! - `json/<path>`: layout + per-chip heights read from a JSON file. Pass any positional arg
//!   ending in `.json` after `--`; the path doubles as both the file source and the bench-ID
//!   suffix that Criterion's filter matches against.
//! - `real/<program>`: trace from an actual zkVM execution of one of the included sample programs.
//!
//! Filter individual variants via Criterion's CLI, e.g.
//! `cargo bench -p sp1-gpu-jagged-sumcheck --bench jagged -- random`,
//! `... --bench jagged -- real/keccak256`, or
//! `... --bench jagged -- /path/to/layout.json`.

use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use slop_algebra::AbstractField;
use slop_challenger::IopCtx;
use slop_futures::queue::WorkerQueue;
use slop_multilinear::Point;
use sp1_core_machine::io::SP1Stdin;
use sp1_core_machine::riscv::RiscvAir;
use sp1_gpu_cudart::{run_in_place, run_sync_in_place, DevicePoint, PinnedBuffer, TaskScope};
use sp1_gpu_jagged_sumcheck::{generate_jagged_sumcheck_poly, jagged_sumcheck};
use sp1_gpu_jagged_tracegen::test_utils::tracegen_setup::{
    self, CORE_MAX_LOG_ROW_COUNT, LOG_STACKING_HEIGHT,
};
use sp1_gpu_jagged_tracegen::{full_tracegen, CORE_MAX_TRACE_SIZE};
use sp1_gpu_utils::config::{Ext, Felt, TestGC};
use sp1_gpu_utils::test_utils::random::{
    random_jagged_trace_mle, random_jagged_trace_mle_from_json,
};
use sp1_gpu_utils::JaggedTraceMle;
use sp1_hypercube::prover::ProverSemaphore;

/// Run the jagged sumcheck timing loop against an already-on-device trace MLE. `id` shows up
/// under the `jagged_sumcheck` Criterion group.
fn run_jagged_sumcheck(
    c: &mut Criterion,
    id: BenchmarkId,
    scope: &TaskScope,
    device_mle: &JaggedTraceMle<Felt, TaskScope>,
) {
    let mut rng = StdRng::seed_from_u64(42);

    // The jagged sumcheck operates over `column_heights.len()` logical columns.
    let log_col_count = device_mle.column_heights.len().next_power_of_two().ilog2();

    let z_row_host = Point::<Ext>::rand(&mut rng, CORE_MAX_LOG_ROW_COUNT);
    let z_col_host = Point::<Ext>::rand(&mut rng, log_col_count);
    let z_row_device = DevicePoint::from_host(&z_row_host, scope).unwrap().into_inner();
    let z_col_device = DevicePoint::from_host(&z_col_host, scope).unwrap().into_inner();

    // Correctness isn't tested here; an arbitrary claim is fine.
    let claim = Ext::zero();

    let mut group = c.benchmark_group("jagged_sumcheck");
    group.sample_size(10);
    group.bench_with_input(id, &(), |b, _| {
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

fn bench_random(c: &mut Criterion) {
    const TOTAL_AREA: u64 = 1 << 25;

    run_sync_in_place(|scope| {
        let mut rng = StdRng::seed_from_u64(42);
        let machine = RiscvAir::<Felt>::machine();
        let device_mle = random_jagged_trace_mle::<Felt, _, _>(
            &mut rng,
            machine.chips(),
            TOTAL_AREA,
            LOG_STACKING_HEIGHT,
        )
        .into_device(&scope);

        let id = BenchmarkId::new("random", format!("total_area_2^{}", TOTAL_AREA.ilog2()));
        run_jagged_sumcheck(c, id, &scope, &device_mle);
    })
    .unwrap();
}

fn bench_json(c: &mut Criterion) {
    // Pick up any positional CLI arg ending in `.json` as a layout file. The path doubles as
    // the bench-ID parameter so Criterion's substring filter matches the same arg.
    let paths: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| !a.starts_with('-') && a.ends_with(".json"))
        .collect();

    if paths.is_empty() {
        return;
    }

    for path in paths {
        let c: &mut Criterion = &mut *c;
        run_sync_in_place(|scope| {
            let mut rng = StdRng::seed_from_u64(42);
            let device_mle =
                random_jagged_trace_mle_from_json::<Felt, _>(&mut rng, &path, LOG_STACKING_HEIGHT)
                    .expect("failed to read JSON layout")
                    .into_device(&scope);

            let id = BenchmarkId::new("json", &path);
            run_jagged_sumcheck(c, id, &scope, &device_mle);
        })
        .unwrap();
    }
}

/// The set of zkVM sample programs available under `jagged_sumcheck/real/<name>`. Add entries to
/// this list to make additional programs benchable; user filters them with Criterion's CLI.
fn real_programs() -> Vec<(&'static str, &'static [u8])> {
    vec![
        ("fibonacci", &test_artifacts::FIBONACCI_ELF),
        ("ed25519", &test_artifacts::ED25519_ELF),
        ("keccak256", &test_artifacts::KECCAK256_ELF),
        ("sha2", &test_artifacts::SHA2_ELF),
    ]
}

fn bench_real(c: &mut Criterion) {
    // Mirror Criterion's CLI filter so we skip the (heavy) tracegen for programs the user
    // isn't asking for. Any positional arg after `--` is treated as a substring match against
    // the bench ID, the same way Criterion's harness uses it for measurement filtering.
    let positional: Vec<String> =
        std::env::args().skip(1).filter(|a| !a.starts_with('-')).collect();
    let matches = |name: &str| -> bool {
        if positional.is_empty() {
            return true;
        }
        let id = format!("real/{name}");
        positional.iter().any(|f| id.contains(f) || f.contains(&id))
    };

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    for (name, elf) in real_programs().into_iter().filter(|(name, _)| matches(name)) {
        // Reborrow `c` per iteration so the inner `async move` doesn't consume it.
        let c: &mut Criterion = &mut *c;
        rt.block_on(async {
            let (machine, record, program) = tracegen_setup::setup(elf, SP1Stdin::new()).await;

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

                let id = BenchmarkId::new("real", name);
                run_jagged_sumcheck(c, id, &scope, &jagged_trace_data);
            })
            .await;
        });
    }
}

criterion_group!(benches, bench_random, bench_json, bench_real);
criterion_main!(benches);
