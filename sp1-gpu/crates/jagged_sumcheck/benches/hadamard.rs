use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use rand::{
    distributions::{Distribution, Standard},
    rngs::StdRng,
    Rng, SeedableRng,
};
use slop_algebra::AbstractField;
use slop_alloc::{Buffer, CpuBackend};
use slop_challenger::IopCtx;
use slop_multilinear::Mle;
use slop_tensor::{Dimensions, Tensor};
use sp1_gpu_cudart::{DeviceBuffer, DeviceCopy, TaskScope};
use sp1_gpu_jagged_sumcheck::simple_hadamard_sumcheck;
use sp1_gpu_jagged_tracegen::test_utils::{
    bench_utils::{with_trace_source, SizeOnlyKind},
    tracegen_setup::CORE_MAX_LOG_ROW_COUNT,
};
use sp1_gpu_utils::config::{Ext, Felt, TestGC};

fn random_buffer<T, R>(rng: &mut R, len: usize) -> Buffer<T, CpuBackend>
where
    Standard: Distribution<T>,
    R: Rng,
{
    rng.sample_iter(Standard).take(len).collect::<Vec<_>>().into()
}

fn upload_mle<T: DeviceCopy>(host: &Buffer<T, CpuBackend>, scope: &TaskScope) -> Mle<T, TaskScope> {
    let storage = DeviceBuffer::from_host(host, scope).unwrap().into_inner();
    let dimensions = Dimensions::try_from([1, host.len()]).unwrap();
    Mle::new(Tensor { storage, dimensions })
}

fn bench_hadamard_sumcheck(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(42);
    with_trace_source(
        c,
        &mut rng,
        SizeOnlyKind,
        CORE_MAX_LOG_ROW_COUNT,
        |c, _id, scope, rng, log_area| {
        let len = 1usize << log_area;
        let base_host: Buffer<Felt, CpuBackend> = random_buffer(rng, len);
        let ext_host: Buffer<Ext, CpuBackend> = random_buffer(rng, len);
        let base = upload_mle(&base_host, scope);
        let ext = upload_mle(&ext_host, scope);

        // Correctness isn't tested here; an arbitrary claim is fine.
        let claim = Ext::zero();

        let mut challenger = TestGC::default_challenger();

        let mut group = c.benchmark_group("hadamard_sumcheck");
        group.bench_function(format!("num_vars_{log_area}"), |b| {
            b.iter_batched(
                || {
                    let out = (base.clone(), ext.clone());
                    scope.synchronize_blocking().unwrap();
                    out
                },
                |(base, ext)| {
                    let result = simple_hadamard_sumcheck(base, ext, &mut challenger, claim);
                    // Wait for any GPU work left enqueued before stopping the timer.
                    scope.synchronize_blocking().unwrap();
                    black_box(result)
                },
                BatchSize::PerIteration,
            );
        });
        group.finish();
    });
}

criterion_group!(benches, bench_hadamard_sumcheck);
criterion_main!(benches);
