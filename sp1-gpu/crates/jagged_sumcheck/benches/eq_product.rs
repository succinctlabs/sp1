//! Criterion bench for the GPU eq-prefixed degree-(K+1) product sumcheck — Option 1 of the
//! two-stage-GKR comparison.  K is fixed at 64 (the actual jagged-assist parameter); LOG_AREA
//! controls total data 2^LOG_AREA via the existing `random:N[,M,...]` CLI sweep.
//!
//!   cargo bench -p sp1-gpu-jagged-sumcheck --bench eq_product -- random:18,20,22,24,26,28

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
use sp1_gpu_jagged_sumcheck::simple_eq_product_sumcheck;
use sp1_gpu_jagged_tracegen::test_utils::bench_utils::{with_trace_source, SizeOnlyKind};
use sp1_gpu_jagged_tracegen::test_utils::tracegen_setup::CORE_MAX_LOG_ROW_COUNT;
use sp1_gpu_utils::config::{Ext, Felt, TestGC};

const K: usize = 64;

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

fn bench_eq_product_sumcheck(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(42);
    with_trace_source(
        c,
        &mut rng,
        SizeOnlyKind,
        CORE_MAX_LOG_ROW_COUNT,
        |c, _id, scope, rng, log_area| {
            let total_len = 1usize << log_area;
            if total_len < K {
                return;
            }
            let mle_height = total_len / K;
            let n_vars = mle_height.trailing_zeros();
            if n_vars == 0 {
                return;
            }

            let base_host: Buffer<Felt, CpuBackend> = random_buffer(rng, total_len);
            let mles = upload_packed(&base_host, K, mle_height, scope);

            // Random ζ ∈ EF^n and z ∈ EF^K, generated once per log_area.
            let zeta: Vec<Ext> =
                rng.sample_iter::<Ext, _>(Standard).take(n_vars as usize).collect();
            let z: Vec<Ext> = rng.sample_iter::<Ext, _>(Standard).take(K).collect();

            let claim = Ext::zero();

            let mut group = c.benchmark_group("eq_product_sumcheck_gpu");
            group.bench_function(format!("log_area_{log_area}_k_{K}"), |b| {
                b.iter_batched(
                    || {
                        let m = mles.clone();
                        scope.synchronize_blocking().unwrap();
                        (m, zeta.clone(), z.clone())
                    },
                    |(m, zeta, z)| {
                        let mut challenger = TestGC::default_challenger();
                        let result = simple_eq_product_sumcheck(m, zeta, z, &mut challenger, claim);
                        scope.synchronize_blocking().unwrap();
                        black_box(result)
                    },
                    BatchSize::PerIteration,
                );
            });
            group.finish();
        },
    );
}

criterion_group!(benches, bench_eq_product_sumcheck);
criterion_main!(benches);
