#![allow(clippy::disallowed_types)]
#![allow(dead_code)]

include!("common.rs");

// ============================================================================
// Single MLE benchmark
// ============================================================================

#[test]
fn benchmark_zk_vs_standard_sumcheck_with_pcs() {
    let num_encoding_variables: u32 = 16;
    let log_num_polynomials: u32 = 8;
    let num_variables = log_num_polynomials + num_encoding_variables;

    eprintln!("\n========================================");
    eprintln!("Benchmark: ZK vs Standard Sumcheck + PCS");
    eprintln!("  Total variables: {num_variables}");
    eprintln!("  MLE size: 2^{num_variables} = {}", 1u64 << num_variables);
    eprintln!("  Stacking: log_num_polynomials={log_num_polynomials}, num_encoding_variables={num_encoding_variables}");
    eprintln!("========================================\n");

    let mut rng = ChaCha20Rng::from_entropy();
    let (original_mle, mle_ef, claim) = generate_random_mle(&mut rng, num_variables);

    // Warmup
    {
        let warmup_mle = mle_ef.clone();
        let mut warmup_challenger = GC::default_challenger();
        let _ = reduce_sumcheck_to_evaluation::<F, EF, _>(
            vec![warmup_mle],
            &mut warmup_challenger,
            vec![claim],
            1,
            EF::one(),
        );
    }

    let (std_p, std_v) = run_standard_single(
        &original_mle,
        &mle_ef,
        claim,
        num_encoding_variables,
        log_num_polynomials,
        num_variables,
    );
    eprintln!("  Standard prover:   {std_p:?}");
    eprintln!("  Standard verifier: {std_v:?}");

    let (zk_p, zk_v) = run_zk_single(
        &original_mle,
        &mle_ef,
        claim,
        num_encoding_variables,
        log_num_polynomials,
        num_variables,
        &mut rng,
    );
    eprintln!("  ZK prover:         {zk_p:?}");
    eprintln!("  ZK verifier:       {zk_v:?}");

    eprintln!("\n===== SUMMARY =====");
    eprintln!("  Prover overhead:   {:.2}x", zk_p.as_secs_f64() / std_p.as_secs_f64());
    eprintln!("  Verifier overhead: {:.2}x", zk_v.as_secs_f64() / std_v.as_secs_f64());
}

// ============================================================================
// Hadamard benchmark
// ============================================================================

#[test]
fn benchmark_zk_vs_standard_hadamard_sumcheck_with_pcs() {
    let num_encoding_variables: u32 = 16;
    let log_num_polynomials: u32 = 8;
    let num_variables = log_num_polynomials + num_encoding_variables;

    eprintln!("\n========================================");
    eprintln!("Benchmark: ZK vs Standard Hadamard Sumcheck + PCS");
    eprintln!("  Total variables: {num_variables}");
    eprintln!("  MLE size: 2^{num_variables} = {}", 1u64 << num_variables);
    eprintln!("  Stacking: log_num_polynomials={log_num_polynomials}, num_encoding_variables={num_encoding_variables}");
    eprintln!("========================================\n");

    let mut rng = ChaCha20Rng::from_entropy();
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

    let (std_p, std_v, std_bytes) = run_standard_hadamard(
        &mle_1,
        &mle_2,
        hadamard_product.clone(),
        claim,
        num_encoding_variables,
        log_num_polynomials,
        num_variables,
    );
    eprintln!("  Standard prover:   {std_p:?}");
    eprintln!("  Standard verifier: {std_v:?}");
    eprintln!("  Standard proof:    {std_bytes} bytes");

    let (zk_p, zk_v, zk_bytes) = run_zk_hadamard(
        &mle_1,
        &mle_2,
        hadamard_product,
        claim,
        num_encoding_variables,
        log_num_polynomials,
        num_variables,
        &mut rng,
    );
    eprintln!("  ZK prover:         {zk_p:?}");
    eprintln!("  ZK verifier:       {zk_v:?}");
    eprintln!("  ZK proof:          {zk_bytes} bytes");

    let fe = std::mem::size_of::<F>() as u64;
    eprintln!("\n===== SUMMARY =====");
    eprintln!("  Prover overhead:   {:.2}x", zk_p.as_secs_f64() / std_p.as_secs_f64());
    eprintln!("  Verifier overhead: {:.2}x", zk_v.as_secs_f64() / std_v.as_secs_f64());
    eprintln!(
        "  Proof overhead:    {:.2}x ({} vs {} felts)",
        zk_bytes as f64 / std_bytes as f64,
        zk_bytes / fe,
        std_bytes / fe,
    );
}
