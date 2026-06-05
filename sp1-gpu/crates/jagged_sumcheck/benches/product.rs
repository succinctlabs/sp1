//! Sweeps the degree-K product sumcheck over K ∈ {2, 4, 8, 16, 32, 64} at a fixed total
//! data size of 64 × 2^c (i.e. log_area = c + 6).  Each iteration measures one full
//! sumcheck against a freshly-uploaded `[K, 2^(log_area - log2 K)]` MLE.

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
use sp1_gpu_jagged_sumcheck::simple_product_sumcheck;
use sp1_gpu_jagged_tracegen::test_utils::bench_utils::{with_trace_source, SizeOnlyKind};
use sp1_gpu_jagged_tracegen::test_utils::tracegen_setup::CORE_MAX_LOG_ROW_COUNT;
use sp1_gpu_utils::config::{Ext, Felt, TestGC};

const K_VALUES: &[usize] = &[2, 4, 8, 16, 32, 64];

fn random_buffer<T, R>(rng: &mut R, len: usize) -> Buffer<T, CpuBackend>
where
    Standard: Distribution<T>,
    R: Rng,
{
    rng.sample_iter(Standard).take(len).collect::<Vec<_>>().into()
}

fn upload_packed<T: DeviceCopy>(
    host: &Buffer<T, CpuBackend>,
    k: usize,
    mle_height: usize,
    scope: &TaskScope,
) -> Mle<T, TaskScope> {
    debug_assert_eq!(host.len(), k * mle_height);
    let storage = DeviceBuffer::from_host(host, scope).unwrap().into_inner();
    let dimensions = Dimensions::try_from([k, mle_height]).unwrap();
    Mle::new(Tensor { storage, dimensions })
}

fn bench_product_sumcheck(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(42);
    with_trace_source(
        c,
        &mut rng,
        SizeOnlyKind,
        CORE_MAX_LOG_ROW_COUNT,
        |c, _id, scope, rng, log_area| {
            let total_len = 1usize << log_area;
            let base_host: Buffer<Felt, CpuBackend> = random_buffer(rng, total_len);

            let mut group = c.benchmark_group("product_sumcheck");
            for &k in K_VALUES {
                if total_len < k {
                    continue;
                }
                let mle_height = total_len / k;
                let n_vars = mle_height.trailing_zeros();
                // Skip degenerate cases where there are no sumcheck rounds.
                if n_vars == 0 {
                    continue;
                }

                let mles = upload_packed(&base_host, k, mle_height, scope);

                let claim = Ext::zero();
                let mut challenger = TestGC::default_challenger();

                group.bench_function(format!("log_area_{log_area}_k_{k}"), |b| {
                    b.iter_batched(
                        || {
                            let m = mles.clone();
                            scope.synchronize_blocking().unwrap();
                            m
                        },
                        |m| {
                            let result = simple_product_sumcheck(k, m, &mut challenger, claim);
                            scope.synchronize_blocking().unwrap();
                            black_box(result)
                        },
                        BatchSize::PerIteration,
                    );
                });
            }
            group.finish();
        },
    );
}

criterion_group!(benches, bench_product_sumcheck);
criterion_main!(benches);
