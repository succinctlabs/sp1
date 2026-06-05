#![allow(clippy::disallowed_types)]
//! Criterion bench for the eq-prefixed degree-(K+1) product sumcheck — Option 1 of the
//! two-stage-GKR comparison.  K is fixed at 64 (the actual jagged-assist parameter); we
//! sweep total data size 2^LOG_AREA via the `LOG_AREAS` env var.
//!
//!   LOG_AREAS=18,20,22 cargo bench -p slop-jagged --bench eq_product
//!
//! The bench passes `Ext::zero()` as the initial claim (correctness is exercised by the
//! corresponding test); we only measure the round-by-round prover work here.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use rand::{distributions::Standard, rngs::StdRng, Rng, SeedableRng};
use slop_algebra::{extension::BinomialExtensionField, AbstractField};
use slop_challenger::{CanSample, IopCtx};
use slop_jagged::EqProductPoly;
use slop_koala_bear::{KoalaBear, KoalaBearDegree4Duplex};
use slop_multilinear::Mle;
use slop_sumcheck::reduce_sumcheck_to_evaluation;

type F = KoalaBear;
type EF = BinomialExtensionField<KoalaBear, 4>;

/// Number of factor MLEs in the product.  Fixed at 64 for the two-stage-GKR Option 1 shape.
const K: usize = 64;

/// Default total-data exponent when `LOG_AREAS` env var is not set.
const DEFAULT_LOG_AREA: u32 = 18;

fn log_areas_from_env() -> Vec<u32> {
    match std::env::var("LOG_AREAS") {
        Ok(s) => {
            let parsed: Vec<u32> =
                s.split(',').filter_map(|p| p.trim().parse::<u32>().ok()).collect();
            if parsed.is_empty() {
                vec![DEFAULT_LOG_AREA]
            } else {
                parsed
            }
        }
        Err(_) => vec![DEFAULT_LOG_AREA],
    }
}

fn bench_eq_product_sumcheck(c: &mut Criterion) {
    let log_areas = log_areas_from_env();
    let mut group = c.benchmark_group("eq_product_sumcheck_cpu");
    for &log_area in &log_areas {
        let total_len = 1usize << log_area;
        if total_len < K {
            continue;
        }
        let mle_height = total_len / K;
        let n_vars = mle_height.trailing_zeros();
        if n_vars == 0 {
            continue;
        }

        // Build inputs once per log_area.  Allocation is excluded from the timed region.
        let mut rng = StdRng::seed_from_u64(0xbada_55ed);
        let batched = Mle::<F>::rand(&mut rng, K, n_vars);
        let zeta: Vec<EF> =
            (&mut rng).sample_iter::<EF, _>(Standard).take(n_vars as usize).collect();
        let z: Vec<EF> = (&mut rng).sample_iter::<EF, _>(Standard).take(K).collect();
        let poly = EqProductPoly::new(batched, zeta, z);

        let claim = EF::zero();

        group.bench_function(format!("log_area_{log_area}_k_{K}"), |b| {
            b.iter_batched(
                || poly.clone(),
                |p| {
                    let mut challenger = KoalaBearDegree4Duplex::default_challenger();
                    let lambda: EF = challenger.sample();
                    let result = reduce_sumcheck_to_evaluation::<F, EF, _>(
                        vec![p],
                        &mut challenger,
                        vec![claim],
                        1,
                        lambda,
                    );
                    black_box(result)
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_eq_product_sumcheck);
criterion_main!(benches);
