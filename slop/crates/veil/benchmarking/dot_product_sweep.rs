#![allow(clippy::disallowed_types, clippy::disallowed_methods)]

//! Batched zk dot-product (lincheck) benchmark: **commit / prove / verify, timed separately**.
//!
//! Proves `<w_j, x> = v_j` for `K` committed vectors against one shared public vector `x` — the
//! `zk_dot_product` protocol standing alone. Mirrors the phase split of the cuPQC GPU example so the
//! two can be compared directly.
//!
//! Phases are reported separately on purpose: a single end-to-end number is the easiest way to hide
//! that one phase dominates for an uninteresting reason.
//!
//! Run (native rate 16):
//!   `cargo run --example dot_product_sweep --release -p slop-veil`
//! Run at a matched rate (e.g. to compare against a rate-4 implementation):
//!   `VEIL_CODE_INVERSE_RATE=4 cargo run --example dot_product_sweep --release -p slop-veil`
//!
//! Note on fairness: this API commits `Vec<EF>` (extension-field) data, so `K` vectors become
//! `(K+1)*D` base-field NTT planes and `4*(K+1)`-wide Merkle leaves. An implementation that commits
//! *base*-field data does `K+D` planes for the same statement. Plane/leaf counts are printed so the
//! comparison can account for it rather than silently absorbing it into a speedup number.

use std::fs::File;
use std::io::Write;
use std::iter::repeat_with;

#[path = "common.rs"]
#[allow(dead_code)]
mod common;
use common::*;

use rand::Rng;
use slop_challenger::IopCtx;
use slop_koala_bear::KoalaBearDegree4Duplex;
use slop_merkle_tree::Poseidon2KoalaBear16Prover;
use slop_veil::zk::dot_product::{
    dot_product, verify_zk_dot_product, zk_dot_product_commitment, zk_dot_product_proof,
};
use slop_veil::zk::error_correcting_code::RsInterpolation;

type GC = KoalaBearDegree4Duplex;
type EFf = <GC as IopCtx>::EF;
/// Coset-LDE interpolation code — the variant the GPU example implements (INTT -> coset-scale -> NTT).
type Code = RsInterpolation<EFf>;
/// Extension degree: an `EF` column is `D` base-field NTT planes.
const D: usize = 4;

struct Row {
    k: usize,
    n: usize,
    code_length: usize,
    total_padding: usize,
    queries: usize,
    commit: Duration,
    commit_sd: f64,
    prove: Duration,
    prove_sd: f64,
    verify: Duration,
    verify_sd: f64,
}

fn bench(k: usize, n: usize, warmup: usize, measured: usize) -> Row {
    let mut rng = ChaCha20Rng::seed_from_u64(2024);
    let merkleizer = Poseidon2KoalaBear16Prover::default();

    // K committed vectors + one shared public vector, all length n.
    let in_vecs: Vec<Vec<EFf>> =
        (0..k).map(|_| repeat_with(|| rng.gen()).take(n).collect()).collect();
    let dot_vec: Vec<EFf> = repeat_with(|| rng.gen()).take(n).collect();
    let expected: Vec<EFf> = in_vecs.iter().map(|w| dot_product(w, &dot_vec)).collect();

    let mut commit_s = Vec::with_capacity(measured);
    let mut prove_s = Vec::with_capacity(measured);
    let mut verify_s = Vec::with_capacity(measured);

    // Filled from the first iteration's prover data (`parameters` is public there; the proof's copy
    // is not, and `claimed_dot_products()` is the only public accessor on the total proof).
    let mut params = None;

    for i in 0..(warmup + measured) {
        let measure = i >= warmup;

        // ---- commit (depends only on the secret vectors) ----
        let t0 = Instant::now();
        let (commitment, prover_data) =
            zk_dot_product_commitment::<GC, _, _, Code>(&in_vecs, &mut rng, &merkleizer).unwrap();
        let t_commit = t0.elapsed();

        if params.is_none() {
            params = Some(prover_data.parameters.clone());
        }

        // ---- prove (consumes prover_data; clone so the commit isn't re-done per iteration) ----
        let mut challenger = GC::default_challenger();
        let t1 = Instant::now();
        let total_proof = zk_dot_product_proof::<GC, _, Code>(
            &dot_vec,
            &commitment,
            prover_data.clone(),
            &mut challenger,
            &merkleizer,
        )
        .unwrap();
        let t_prove = t1.elapsed();

        // ---- verify ----
        let mut challenger = GC::default_challenger();
        let t2 = Instant::now();
        verify_zk_dot_product::<GC, Code>(&commitment, &dot_vec, &total_proof, &mut challenger)
            .unwrap();
        let t_verify = t2.elapsed();

        // Correctness gate: a benchmark that silently proves the wrong thing is worthless.
        assert_eq!(total_proof.claimed_dot_products(), expected, "claims must be the true dots");

        if measure {
            commit_s.push(t_commit);
            prove_s.push(t_prove);
            verify_s.push(t_verify);
        }

        if i == 0 {
            let p = params.as_ref().unwrap();
            eprintln!(
                "  [K={k:4} n={n:5}] rate={:<4} padded_len={} code_len={} pad={} queries={} \
                 | base_planes={} leaf_w={}",
                p.code_inverse_rate,
                p.padded_message_length,
                p.code_length,
                p.total_padding,
                p.evals(1),
                (k + 1) * D,
                (k + 1) * D,
            );
        }
    }

    let p_params = params.unwrap();

    Row {
        k,
        n,
        code_length: p_params.code_length,
        total_padding: p_params.total_padding,
        queries: p_params.evals(1),
        commit: median(&mut commit_s),
        commit_sd: stddev_ms(&commit_s),
        prove: median(&mut prove_s),
        prove_sd: stddev_ms(&prove_s),
        verify: median(&mut verify_s),
        verify_sd: stddev_ms(&verify_s),
    }
}

fn main() {
    // Iteration counts default to 1 warm-up + 5 measured; override via DOT_BENCH_WARMUP /
    // DOT_BENCH_MEASURED (e.g. to run the much slower single-threaded sweep with fewer repeats).
    let env_usize = |k: &str, d: usize| {
        std::env::var(k).ok().and_then(|s| s.parse().ok()).unwrap_or(d)
    };
    let num_warmup = env_usize("DOT_BENCH_WARMUP", 1);
    let num_measured = env_usize("DOT_BENCH_MEASURED", 5);

    // (K, n). n = 512 matches the GPU example's MSG_N; the K sweep shows how each phase scales with
    // the batch (the GPU example's headline claim is that verify is O(1) in K). Override the batch
    // widths with DOT_BENCH_KS=1,2,4,... and the length with DOT_BENCH_N=<n>.
    let n: usize =
        std::env::var("DOT_BENCH_N").ok().and_then(|s| s.parse().ok()).unwrap_or(512);
    let configs: Vec<(usize, usize)> = match std::env::var("DOT_BENCH_KS") {
        Ok(s) => s.split(',').filter_map(|k| k.trim().parse().ok()).map(|k| (k, n)).collect(),
        Err(_) => vec![(1, 512), (8, 512), (64, 512), (512, 512), (1, 4096)],
    };

    let rate: f64 = std::env::var("VEIL_CODE_INVERSE_RATE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(16.0);

    eprintln!("zk dot-product sweep — CPU (slop-veil), code = RsInterpolation, GC = KoalaBearDegree4Duplex");
    eprintln!("inverse rate = {rate}  (set VEIL_CODE_INVERSE_RATE to change)");
    eprintln!("warmup = {num_warmup}, measured = {num_measured} (median reported)\n");

    let rows: Vec<Row> =
        configs.iter().map(|&(k, n)| bench(k, n, num_warmup, num_measured)).collect();

    let out = concat!(env!("CARGO_MANIFEST_DIR"), "/benchmarking/dot_product_sweep_results.csv");
    let mut file = File::create(out).expect("create csv");
    writeln!(
        file,
        "k,n,inverse_rate,code_length,total_padding,queries,base_planes,leaf_width,\
         commit_median_ms,commit_stddev_ms,prove_median_ms,prove_stddev_ms,\
         verify_median_ms,verify_stddev_ms"
    )
    .unwrap();

    eprintln!("\n{:>5} {:>6} {:>12} {:>12} {:>12}", "K", "n", "commit_ms", "prove_ms", "verify_ms");
    for r in &rows {
        writeln!(
            file,
            "{},{},{},{},{},{},{},{},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3}",
            r.k,
            r.n,
            rate,
            r.code_length,
            r.total_padding,
            r.queries,
            (r.k + 1) * D,
            (r.k + 1) * D,
            r.commit.as_secs_f64() * 1000.0,
            r.commit_sd,
            r.prove.as_secs_f64() * 1000.0,
            r.prove_sd,
            r.verify.as_secs_f64() * 1000.0,
            r.verify_sd,
        )
        .unwrap();
        eprintln!(
            "{:>5} {:>6} {:>12.2} {:>12.2} {:>12.2}",
            r.k,
            r.n,
            r.commit.as_secs_f64() * 1000.0,
            r.prove.as_secs_f64() * 1000.0,
            r.verify.as_secs_f64() * 1000.0,
        );
    }
    eprintln!("\nwrote {out}");
}
