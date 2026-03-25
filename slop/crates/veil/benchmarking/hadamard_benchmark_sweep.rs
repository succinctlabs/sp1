#![allow(clippy::disallowed_types)]
#![allow(dead_code)]

//! Hadamard benchmark sweep across multiple parameter configurations.
//!
//! Runs 10 iterations per config and reports all runs + median as CSV.
//!
//! Run: `cargo run --example hadamard_benchmark_sweep --release -p slop-veil`

use std::fs::File;
use std::io::Write;

include!("common.rs");

struct BenchResult {
    std_prover: Duration,
    std_verifier: Duration,
    std_proof_bytes: u64,
    zk_prover: Duration,
    zk_verifier: Duration,
    zk_proof_bytes: u64,
}

fn main() {
    let configs: &[(u32, u32)] = &[(16, 8), (18, 8), (20, 8)];
    let num_iterations = 10;

    let output_path =
        concat!(env!("CARGO_MANIFEST_DIR"), "/benchmarking/hadamard_benchmark_sweep_results.csv");
    let mut file = File::create(output_path).expect("Failed to create output file");

    let header = "num_encoding_variables,log_num_polynomials,num_variables,run,\
         std_prover_ms,std_verifier_ms,std_proof_bytes,\
         zk_prover_ms,zk_verifier_ms,zk_proof_bytes";
    writeln!(file, "{header}").unwrap();
    eprintln!("{header}");

    let mut rng = ChaCha20Rng::from_entropy();

    for &(num_encoding_variables, log_num_polynomials) in configs {
        let num_variables = num_encoding_variables + log_num_polynomials;

        eprintln!(
            "\n--- Config: num_encoding_variables={num_encoding_variables}, \
             log_num_polynomials={log_num_polynomials}, num_variables={num_variables} ---"
        );

        let (mle_1, mle_2, hadamard_product, claim) =
            generate_random_hadamard_product(&mut rng, num_variables);

        // Warmup
        {
            let warmup = hadamard_product.clone();
            let mut warmup_challenger = GC::default_challenger();
            let lambda: EF = slop_challenger::CanSample::sample(&mut warmup_challenger);
            let _ = reduce_sumcheck_to_evaluation::<F, EF, _>(
                vec![warmup],
                &mut warmup_challenger,
                vec![claim],
                1,
                lambda,
            );
        }

        let mut results = Vec::with_capacity(num_iterations);

        for i in 0..num_iterations {
            let (std_p, std_v, std_bytes) = run_standard_hadamard(
                &mle_1,
                &mle_2,
                hadamard_product.clone(),
                claim,
                num_encoding_variables,
                log_num_polynomials,
                num_variables,
            );
            let (zk_p, zk_v, zk_bytes) = run_zk_hadamard(
                &mle_1,
                &mle_2,
                hadamard_product.clone(),
                claim,
                num_encoding_variables,
                log_num_polynomials,
                num_variables,
                &mut rng,
            );

            let line = format!(
                "{num_encoding_variables},{log_num_polynomials},{num_variables},{i},\
                 {:.3},{:.3},{std_bytes},{:.3},{:.3},{zk_bytes}",
                std_p.as_secs_f64() * 1000.0,
                std_v.as_secs_f64() * 1000.0,
                zk_p.as_secs_f64() * 1000.0,
                zk_v.as_secs_f64() * 1000.0,
            );
            writeln!(file, "{line}").unwrap();
            eprintln!("{line}");
            file.flush().unwrap();

            results.push(BenchResult {
                std_prover: std_p,
                std_verifier: std_v,
                std_proof_bytes: std_bytes,
                zk_prover: zk_p,
                zk_verifier: zk_v,
                zk_proof_bytes: zk_bytes,
            });
        }

        // Median row
        let mut std_p: Vec<Duration> = results.iter().map(|r| r.std_prover).collect();
        let mut std_v: Vec<Duration> = results.iter().map(|r| r.std_verifier).collect();
        let mut zk_p: Vec<Duration> = results.iter().map(|r| r.zk_prover).collect();
        let mut zk_v: Vec<Duration> = results.iter().map(|r| r.zk_verifier).collect();

        let line = format!(
            "{num_encoding_variables},{log_num_polynomials},{num_variables},median,\
             {:.3},{:.3},{},{:.3},{:.3},{}",
            median(&mut std_p).as_secs_f64() * 1000.0,
            median(&mut std_v).as_secs_f64() * 1000.0,
            results[0].std_proof_bytes,
            median(&mut zk_p).as_secs_f64() * 1000.0,
            median(&mut zk_v).as_secs_f64() * 1000.0,
            results[0].zk_proof_bytes,
        );
        writeln!(file, "{line}").unwrap();
        eprintln!("{line}");
        file.flush().unwrap();
    }

    eprintln!("\nResults saved to {output_path}");
}
