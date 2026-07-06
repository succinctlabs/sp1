//! Microbenchmark: main-trace **column** generation, CPU vs GPU, for the Add/Sub
//! chips ported to the witgen-interpreter device path.
//!
//! - `cpu`: `MachineAir::generate_trace` (host trace in CPU memory).
//! - `gpu`: `CudaTracegenAir::generate_trace_device` (device-resident trace) —
//!   includes per-event input packing + H2D upload + the interpreter kernel,
//!   synchronized per call.
//!
//! This isolates the column-generation cost (no proving, no byte-lookups — those
//! still run on the host `generate_dependencies` and are the next target). The
//! host path would additionally need an H2D copy to reach the device the GPU path
//! already lands on, so `gpu` is if anything conservatively compared.

use std::time::Instant;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::{rngs::StdRng, Rng, SeedableRng};
use sp1_core_executor::events::{AluEvent, MemoryReadRecord, MemoryRecordEnum};
use sp1_core_executor::{ExecutionRecord, Opcode, RTypeRecord};
use sp1_core_machine::alu::add_sub::{add::AddChip, sub::SubChip};
use sp1_core_machine::SupervisorMode;
use sp1_gpu_cudart::TaskScope;
use sp1_gpu_tracegen::CudaTracegenAir;
use sp1_hypercube::air::MachineAir;
use sp1_primitives::SP1Field as F;

const LOG_SIZES: [u32; 4] = [14, 16, 18, 20];

fn read(rng: &mut StdRng) -> MemoryRecordEnum {
    let prev_timestamp = rng.gen::<u32>() as u64;
    let timestamp = prev_timestamp + 1 + (rng.gen::<u32>() as u64);
    MemoryRecordEnum::Read(MemoryReadRecord {
        value: rng.gen::<u32>() as u64,
        timestamp,
        prev_timestamp,
        prev_page_prot_record: None,
    })
}

fn gen_events(n: usize, opcode: Opcode, rng: &mut StdRng) -> Vec<(AluEvent, RTypeRecord)> {
    (0..n)
        .map(|i| {
            let b = rng.gen::<u32>() as u64;
            let c = rng.gen::<u32>() as u64;
            let a = if opcode == Opcode::ADD { b.wrapping_add(c) } else { b.wrapping_sub(c) };
            let alu = AluEvent::new((i as u64) * 8 + 8, (i as u64) * 4 + 4, opcode, a, b, c, false);
            let record = RTypeRecord {
                op_a: rng.gen_range(1..32),
                a: read(rng),
                op_b: b,
                b: read(rng),
                op_c: c,
                c: read(rng),
                is_untrusted: false,
            };
            (alu, record)
        })
        .collect()
}

/// Bench one chip: `cpu` (host generate_trace) and `gpu` (device generate_trace).
macro_rules! bench_chip {
    ($c:expr, $rt:expr, $name:literal, $chip_ty:ty, $opcode:expr, $field:ident) => {{
        let mut group = $c.benchmark_group($name);
        for &log_size in LOG_SIZES.iter() {
            let n = 1usize << log_size;
            let mut rng = StdRng::seed_from_u64(0xBEEF + log_size as u64);
            let events = gen_events(n, $opcode, &mut rng);
            group.throughput(Throughput::Elements(n as u64));

            // CPU: host trace generation.
            group.bench_with_input(BenchmarkId::new("cpu", n), &n, |b, _| {
                let shard = ExecutionRecord { $field: events.clone(), ..Default::default() };
                let chip = <$chip_ty>::default();
                b.iter(|| {
                    let t = MachineAir::<F>::generate_trace(
                        &chip,
                        &shard,
                        &mut ExecutionRecord::default(),
                    );
                    black_box(t);
                });
            });

            // GPU: device-resident trace generation (packing + upload + kernel).
            group.bench_with_input(BenchmarkId::new("gpu", n), &n, |b, _| {
                let events = events.clone();
                b.iter_custom(|iters| {
                    let events = events.clone();
                    $rt.block_on(async move {
                        sp1_gpu_cudart::spawn(move |scope: TaskScope| async move {
                            let shard = ExecutionRecord { $field: events, ..Default::default() };
                            let chip = <$chip_ty>::default();
                            // Warmup (kernel JIT, allocations).
                            let _ = chip
                                .generate_trace_device(
                                    &shard,
                                    &mut ExecutionRecord::default(),
                                    &scope,
                                )
                                .await
                                .unwrap();
                            scope.synchronize_blocking().unwrap();

                            let start = Instant::now();
                            for _ in 0..iters {
                                let t = chip
                                    .generate_trace_device(
                                        &shard,
                                        &mut ExecutionRecord::default(),
                                        &scope,
                                    )
                                    .await
                                    .unwrap();
                                scope.synchronize_blocking().unwrap();
                                black_box(&t);
                            }
                            start.elapsed()
                        })
                        .await
                        .unwrap()
                    })
                });
            });
        }
        group.finish();
    }};
}

fn bench(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    bench_chip!(c, &rt, "add_tracegen_cols", AddChip<SupervisorMode>, Opcode::ADD, add_events);
    bench_chip!(c, &rt, "sub_tracegen_cols", SubChip<SupervisorMode>, Opcode::SUB, sub_events);
}

criterion_group!(benches, bench);
criterion_main!(benches);
