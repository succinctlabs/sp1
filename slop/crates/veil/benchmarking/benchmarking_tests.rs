#![allow(clippy::disallowed_types)]
#![allow(dead_code)]

include!("common.rs");

// ============================================================================
// Single MLE benchmark
// ============================================================================

#[test]
fn benchmark_zk_vs_standard_sumcheck_with_pcs() {
    let num_stacked_vars: u32 = 16;
    let log_stacking_height: u32 = 8;
    let total_num_vars = log_stacking_height + num_stacked_vars;

    eprintln!("\n========================================");
    eprintln!("Benchmark: ZK vs Standard Sumcheck + PCS");
    eprintln!("  Total variables: {total_num_vars}");
    eprintln!("  MLE size: 2^{total_num_vars} = {}", 1u64 << total_num_vars);
    eprintln!("  Stacking: log_height={log_stacking_height}, stacked_vars={num_stacked_vars}");
    eprintln!("========================================\n");

    let mut rng = ChaCha20Rng::from_entropy();
    let (original_mle, mle_ef, claim) = generate_random_mle(&mut rng, total_num_vars);

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
        num_stacked_vars,
        log_stacking_height,
        total_num_vars,
    );
    eprintln!("  Standard prover:   {std_p:?}");
    eprintln!("  Standard verifier: {std_v:?}");

    let (zk_p, zk_v) = run_zk_single(
        &original_mle,
        &mle_ef,
        claim,
        num_stacked_vars,
        log_stacking_height,
        total_num_vars,
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
    let num_stacked_vars: u32 = 19;
    let log_stacking_height: u32 = 8;
    let total_num_vars = log_stacking_height + num_stacked_vars;

    eprintln!("\n========================================");
    eprintln!("Benchmark: ZK vs Standard Hadamard Sumcheck + PCS");
    eprintln!("  Total variables: {total_num_vars}");
    eprintln!("  MLE size: 2^{total_num_vars} = {}", 1u64 << total_num_vars);
    eprintln!("  Stacking: log_height={log_stacking_height}, stacked_vars={num_stacked_vars}");
    eprintln!("========================================\n");

    let mut rng = ChaCha20Rng::from_entropy();
    let (mle_1, mle_2, hadamard_product, claim) =
        generate_random_hadamard_product(&mut rng, total_num_vars);

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
        num_stacked_vars,
        log_stacking_height,
        total_num_vars,
    );
    eprintln!("  Standard prover:   {std_p:?}");
    eprintln!("  Standard verifier: {std_v:?}");
    eprintln!("  Standard proof:    {std_bytes} bytes");

    let (zk_p, zk_v, zk_bytes) = run_zk_hadamard(
        &mle_1,
        &mle_2,
        hadamard_product,
        claim,
        num_stacked_vars,
        log_stacking_height,
        total_num_vars,
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
