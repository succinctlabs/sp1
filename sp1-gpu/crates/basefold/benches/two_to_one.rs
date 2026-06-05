//! GPU criterion bench for the two 2-to-1 reduction options.
//!
//! Setup (uploading `h` to device) is excluded from the measurement via
//! `iter_batched`; the timed region covers only the prover call
//! (kernel launches + host-side challenger + interpolation).  Option 2
//! consumes the device `h` (it folds in place), so the setup closure
//! produces a fresh `DeviceMle` per iteration.
//!
//! The whole bench function runs inside a single `run_sync_in_place`
//! scope so all benches share the same `TaskScope`.

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use slop_alloc::Buffer;
use slop_challenger::IopCtx;
use slop_multilinear::{Mle, Point};
use slop_tensor::Tensor;
use sp1_gpu_basefold::{prove_two_to_one_option1_gpu, prove_two_to_one_option2_gpu};
use sp1_gpu_cudart::{run_sync_in_place, DeviceBuffer, DeviceMle, DeviceTensor, TaskScope};
use sp1_gpu_utils::Ext;
use sp1_primitives::SP1GlobalContext;

fn random_setup(n: usize, seed: u64) -> (Vec<Ext>, Point<Ext>, Point<Ext>, Ext, Ext) {
    let mut rng = StdRng::seed_from_u64(seed);
    let h_data: Vec<Ext> = (0..(1usize << n)).map(|_| rng.gen()).collect();
    let z: Point<Ext> = (0..n).map(|_| rng.gen()).collect::<Vec<_>>().into();
    let zp: Point<Ext> = (0..n).map(|_| rng.gen()).collect::<Vec<_>>().into();

    let mut tensor_cpu = Tensor::from(h_data.clone());
    tensor_cpu.reshape_in_place([1usize << n, 1usize]);
    let h_cpu = Mle::<Ext>::new(tensor_cpu);
    let claim_z = h_cpu.eval_at(&z).to_vec()[0];
    let claim_zp = h_cpu.eval_at(&zp).to_vec()[0];

    (h_data, z, zp, claim_z, claim_zp)
}

fn upload_h(h_data: &[Ext], n: usize, backend: &TaskScope) -> DeviceMle<Ext> {
    let h_buf_host = Buffer::<Ext>::from(h_data.to_vec());
    let h_dev = DeviceBuffer::from_host(&h_buf_host, backend).unwrap().into_inner();
    let dims = slop_tensor::Dimensions::try_from([1usize, 1usize << n]).unwrap();
    let h_tensor = Tensor { storage: h_dev, dimensions: dims };
    DeviceMle::new(DeviceTensor::from_raw(h_tensor))
}

fn bench_two_to_one_gpu(c: &mut Criterion) {
    run_sync_in_place(|backend| {
        let mut group = c.benchmark_group("two_to_one_gpu");

        for &n in &[18usize, 21] {
            let (h_data, z, zp, claim_z, claim_zp) = random_setup(n, 0xABCDEF ^ (n as u64));

            group.bench_with_input(BenchmarkId::new("option1", n), &n, |b, _| {
                b.iter_batched(
                    || (upload_h(&h_data, n, &backend), SP1GlobalContext::default_challenger()),
                    |(h_mle, mut chal)| {
                        let (f, zpp, claim) =
                            prove_two_to_one_option1_gpu(&h_mle, &z, &zp, &mut chal, &backend);
                        criterion::black_box((f, zpp, claim));
                    },
                    BatchSize::SmallInput,
                );
            });

            group.bench_with_input(BenchmarkId::new("option2", n), &n, |b, _| {
                b.iter_batched(
                    || (upload_h(&h_data, n, &backend), SP1GlobalContext::default_challenger()),
                    |(h_mle, mut chal)| {
                        let (msgs, point, claim) = prove_two_to_one_option2_gpu(
                            h_mle, &z, &zp, claim_z, claim_zp, &mut chal, &backend,
                        );
                        criterion::black_box((msgs, point, claim));
                    },
                    BatchSize::SmallInput,
                );
            });
        }

        group.finish();
    })
    .unwrap();
}

criterion_group!(benches, bench_two_to_one_gpu);
criterion_main!(benches);
