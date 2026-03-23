#![allow(clippy::disallowed_types)]
#![allow(dead_code)]

//! Single MLE benchmark sweep across parameter space.
//!
//! Run: `cargo run --example benchmark_sweep --release -p slop-veil`

use std::fs::File;
use std::io::Write;

include!("common.rs");

fn main() {
    const NUM_WARMUP: usize = 1;
    const NUM_MEASURED: usize = 5;
    const MIN_TOTAL_VARS: u32 = 10;
    const MAX_TOTAL_VARS: u32 = 25;
    const MIN_LOG_STACK: u32 = 5;
    const MAX_LOG_STACK: u32 = 15;

    let output_path =
        concat!(env!("CARGO_MANIFEST_DIR"), "/benchmarking/benchmark_sweep_results.csv");
    let mut file = File::create(output_path).expect("Failed to create output file");

    writeln!(
        file,
        "num_variables,log_num_polynomials,num_encoding_variables,\
         std_prover_median_ms,std_prover_stddev_ms,\
         std_verifier_median_ms,std_verifier_stddev_ms,\
         zk_prover_median_ms,zk_prover_stddev_ms,\
         zk_verifier_median_ms,zk_verifier_stddev_ms,\
         prover_overhead,verifier_overhead"
    )
    .unwrap();
    file.flush().unwrap();

    eprintln!(
        "Benchmark sweep: NUM_VARIABLES {}..{}, LOG_NUM_POLYNOMIALS {}..{}",
        MIN_TOTAL_VARS, MAX_TOTAL_VARS, MIN_LOG_STACK, MAX_LOG_STACK
    );
    eprintln!("Warm-up: {NUM_WARMUP}, Measured iterations: {NUM_MEASURED} (reporting median)");
    eprintln!("Results will be saved to: {output_path}\n");

    let mut rng = ChaCha20Rng::from_entropy();

    for num_variables in MIN_TOTAL_VARS..=MAX_TOTAL_VARS {
        let max_log_stack = MAX_LOG_STACK.min(num_variables - 1);
        for log_num_polynomials in MIN_LOG_STACK..=max_log_stack {
            let num_encoding_variables = num_variables - log_num_polynomials;

            if num_encoding_variables < 10 {
                continue;
            }

            eprint!(
                "num_variables={num_variables}, log_num_polynomials={log_num_polynomials}, \
                 num_encoding_variables={num_encoding_variables} ... "
            );
            std::io::Write::flush(&mut std::io::stdout()).unwrap();

            let (original_mle, mle_ef, claim) = generate_random_mle(&mut rng, num_variables);

            // Warm-up
            for _ in 0..NUM_WARMUP {
                let _ = run_standard_single(
                    &original_mle,
                    &mle_ef,
                    claim,
                    num_encoding_variables,
                    log_num_polynomials,
                    num_variables,
                );
                let _ = run_zk_single(
                    &original_mle,
                    &mle_ef,
                    claim,
                    num_encoding_variables,
                    log_num_polynomials,
                    num_variables,
                    &mut rng,
                );
            }

            let mut std_prover_samples = Vec::with_capacity(NUM_MEASURED);
            let mut std_verifier_samples = Vec::with_capacity(NUM_MEASURED);
            let mut zk_prover_samples = Vec::with_capacity(NUM_MEASURED);
            let mut zk_verifier_samples = Vec::with_capacity(NUM_MEASURED);

            for _ in 0..NUM_MEASURED {
                let (sp, sv) = run_standard_single(
                    &original_mle,
                    &mle_ef,
                    claim,
                    num_encoding_variables,
                    log_num_polynomials,
                    num_variables,
                );
                std_prover_samples.push(sp);
                std_verifier_samples.push(sv);

                let (zp, zv) = run_zk_single(
                    &original_mle,
                    &mle_ef,
                    claim,
                    num_encoding_variables,
                    log_num_polynomials,
                    num_variables,
                    &mut rng,
                );
                zk_prover_samples.push(zp);
                zk_verifier_samples.push(zv);
            }

            let std_p_sd = stddev_ms(&std_prover_samples);
            let std_v_sd = stddev_ms(&std_verifier_samples);
            let zk_p_sd = stddev_ms(&zk_prover_samples);
            let zk_v_sd = stddev_ms(&zk_verifier_samples);

            let std_p = median(&mut std_prover_samples).as_secs_f64() * 1000.0;
            let std_v = median(&mut std_verifier_samples).as_secs_f64() * 1000.0;
            let zk_p = median(&mut zk_prover_samples).as_secs_f64() * 1000.0;
            let zk_v = median(&mut zk_verifier_samples).as_secs_f64() * 1000.0;
            let p_overhead = zk_p / std_p;
            let v_overhead = zk_v / std_v;

            writeln!(
                file,
                "{num_variables},{log_num_polynomials},{num_encoding_variables},\
                 {std_p:.3},{std_p_sd:.3},\
                 {std_v:.3},{std_v_sd:.3},\
                 {zk_p:.3},{zk_p_sd:.3},\
                 {zk_v:.3},{zk_v_sd:.3},\
                 {p_overhead:.4},{v_overhead:.4}"
            )
            .unwrap();
            file.flush().unwrap();

            eprintln!(
                "std_p={std_p:.1}ms(±{std_p_sd:.1}) std_v={std_v:.1}ms(±{std_v_sd:.1}) \
                 zk_p={zk_p:.1}ms(±{zk_p_sd:.1}) zk_v={zk_v:.1}ms(±{zk_v_sd:.1}) \
                 p_oh={p_overhead:.2}x v_oh={v_overhead:.2}x"
            );
        }
    }

    eprintln!("\nDone! Results saved to {output_path}");
}
