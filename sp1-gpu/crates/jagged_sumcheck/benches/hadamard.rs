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
use sp1_gpu_cudart::{run_sync_in_place, DeviceBuffer, DeviceCopy, TaskScope};
use sp1_gpu_jagged_sumcheck::simple_hadamard_sumcheck;
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
    const NUM_VARIABLES: u32 = 25;

    run_sync_in_place(|scope| {
        let mut rng = StdRng::seed_from_u64(42);
        let len = 1usize << NUM_VARIABLES;

        let base_host: Buffer<Felt, CpuBackend> = random_buffer(&mut rng, len);
        let ext_host: Buffer<Ext, CpuBackend> = random_buffer(&mut rng, len);

        // Correctness isn't tested here; an arbitrary claim is fine.
        let claim = Ext::zero();

        let mut group = c.benchmark_group("hadamard_sumcheck");
        group.sample_size(10);
        group.bench_function("num_vars_25", |b| {
            b.iter_batched(
                || {
                    let base = upload_mle(&base_host, &scope);
                    let ext = upload_mle(&ext_host, &scope);
                    let challenger = TestGC::default_challenger();
                    // Drain pending H2D copies before the timer starts.
                    scope.synchronize_blocking().unwrap();
                    (base, ext, challenger)
                },
                |(base, ext, challenger)| {
                    let result = simple_hadamard_sumcheck(base, ext, challenger, claim);
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

criterion_group!(benches, bench_hadamard_sumcheck);
criterion_main!(benches);
