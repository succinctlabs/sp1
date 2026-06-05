//! CPU criterion bench for the two 2-to-1 reduction options.
//!
//! Both options reduce two evaluation claims `(z, A)`, `(z', B)` on the
//! same multilinear `h` to a single claim `(z'', C)`.  This bench measures
//! prover-side cost only; verifier work is microseconds and irrelevant.
//!
//! Data is in the extension field throughout (matches the production
//! setting where `h` is the RLC of base-field traces).

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use slop_algebra::extension::BinomialExtensionField;
use slop_baby_bear::{baby_bear_poseidon2::BabyBearDegree4Duplex, BabyBear};
use slop_challenger::IopCtx;
use slop_multilinear::{prove_two_to_one_option1, prove_two_to_one_option2, Mle, Point};
use slop_tensor::Tensor;

type F = BabyBear;
type EF = BinomialExtensionField<F, 4>;
type Chal = <BabyBearDegree4Duplex as IopCtx>::Challenger;

fn random_setup(n: usize, seed: u64) -> (Mle<EF>, Point<EF>, Point<EF>, EF, EF) {
    let mut rng = StdRng::seed_from_u64(seed);
    let h_data: Vec<EF> = (0..(1usize << n)).map(|_| rng.gen()).collect();
    let mut tensor = Tensor::from(h_data);
    tensor.reshape_in_place([1usize << n, 1usize]);
    let h = Mle::new(tensor);
    let z: Point<EF> = (0..n).map(|_| rng.gen()).collect::<Vec<_>>().into();
    let zp: Point<EF> = (0..n).map(|_| rng.gen()).collect::<Vec<_>>().into();
    let claim_z = h.eval_at(&z).to_vec()[0];
    let claim_zp = h.eval_at(&zp).to_vec()[0];
    (h, z, zp, claim_z, claim_zp)
}

fn bench_two_to_one(c: &mut Criterion) {
    let mut group = c.benchmark_group("two_to_one");
    // log_stacking_height is 18..=21 in production.  Bench the endpoints.
    for &n in &[18usize, 21] {
        let (h, z, zp, az, azp) = random_setup(n, 0xABCDEF ^ (n as u64));

        group.bench_with_input(BenchmarkId::new("option1", n), &n, |b, _| {
            b.iter(|| {
                let mut chal: Chal = BabyBearDegree4Duplex::default_challenger();
                let (proof, z_pp, claim) =
                    prove_two_to_one_option1::<F, EF, _>(&h, &z, &zp, &mut chal);
                criterion::black_box((proof, z_pp, claim));
            });
        });

        group.bench_with_input(BenchmarkId::new("option2", n), &n, |b, _| {
            b.iter(|| {
                let mut chal: Chal = BabyBearDegree4Duplex::default_challenger();
                let (proof, z_pp, claim) =
                    prove_two_to_one_option2::<F, EF, _>(&h, &z, &zp, az, azp, &mut chal);
                criterion::black_box((proof, z_pp, claim));
            });
        });
        let _ = (az, azp);
    }
    group.finish();
}

criterion_group!(benches, bench_two_to_one);
criterion_main!(benches);
