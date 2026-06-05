#![allow(clippy::disallowed_types)]
//! Criterion bench for the two-stage-GKR Option 2 sumcheck (CPU).  K is fixed at 64; sweep
//! the (K_1, K_2) split via the `KSPLITS` env var and total data size via `LOG_AREAS`.
//!
//!   LOG_AREAS=18,20,22 KSPLITS=2x32,4x16,8x8,16x4,32x2 \
//!     cargo bench -p slop-jagged --bench two_stage_eq_product
//!
//! The bench passes `EF::zero()` as the initial claim (correctness is exercised by the
//! corresponding test); we only measure prover work here.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use rand::{distributions::Standard, rngs::StdRng, Rng, SeedableRng};
use slop_algebra::{extension::BinomialExtensionField, AbstractField};
use slop_challenger::IopCtx;
use slop_jagged::simple_two_stage_eq_product_sumcheck;
use slop_koala_bear::{KoalaBear, KoalaBearDegree4Duplex};
use slop_multilinear::Mle;

type F = KoalaBear;
type EF = BinomialExtensionField<KoalaBear, 4>;

/// Total number of inner factors.  Fixed at 64 for the two-stage-GKR Option 2 shape.
const K: usize = 64;

const DEFAULT_LOG_AREA: u32 = 18;
const DEFAULT_SPLITS: &[(usize, usize)] = &[(2, 32), (4, 16), (8, 8), (16, 4), (32, 2)];

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

fn splits_from_env() -> Vec<(usize, usize)> {
    match std::env::var("KSPLITS") {
        Ok(s) => {
            let parsed: Vec<(usize, usize)> = s
                .split(',')
                .filter_map(|tok| {
                    let mut it = tok.trim().split('x');
                    let k1 = it.next()?.parse::<usize>().ok()?;
                    let k2 = it.next()?.parse::<usize>().ok()?;
                    Some((k1, k2))
                })
                .filter(|(k1, k2)| k1 * k2 == K)
                .collect();
            if parsed.is_empty() {
                DEFAULT_SPLITS.to_vec()
            } else {
                parsed
            }
        }
        Err(_) => DEFAULT_SPLITS.to_vec(),
    }
}

fn bench_two_stage_eq_product_sumcheck(c: &mut Criterion) {
    let log_areas = log_areas_from_env();
    let splits = splits_from_env();
    let mut group = c.benchmark_group("two_stage_eq_product_sumcheck_cpu");
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

        // Inputs built once per log_area (same data across all splits — only the protocol
        // partition changes).
        let mut rng = StdRng::seed_from_u64(0xbada_55ed);
        let batched = Mle::<F>::rand(&mut rng, K, n_vars);
        let zeta: Vec<EF> =
            (&mut rng).sample_iter::<EF, _>(Standard).take(n_vars as usize).collect();
        let z: Vec<EF> = (&mut rng).sample_iter::<EF, _>(Standard).take(K).collect();
        let claim = EF::zero();

        for &(k1, k2) in &splits {
            group.bench_function(format!("log_area_{log_area}_k1_{k1}_k2_{k2}"), |b| {
                b.iter_batched(
                    || (batched.clone(), zeta.clone(), z.clone()),
                    |(batched, zeta, z)| {
                        let mut challenger = KoalaBearDegree4Duplex::default_challenger();
                        let result = simple_two_stage_eq_product_sumcheck::<F, EF, _>(
                            batched,
                            zeta,
                            z,
                            k1,
                            k2,
                            claim,
                            &mut challenger,
                        );
                        black_box(result)
                    },
                    BatchSize::PerIteration,
                );
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_two_stage_eq_product_sumcheck);
criterion_main!(benches);
