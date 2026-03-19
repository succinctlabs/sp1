use crate::zk::inner::{
    compute_mask_length, ConstraintContextInnerExt, MleCommitmentIndex, ZkCnstrAndReadingCtxInner,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use slop_challenger::IopCtx;
use slop_koala_bear::KoalaBearDegree4Duplex;
use slop_merkle_tree::Poseidon2KoalaBear16Prover;
use slop_multilinear::{Mle, Point};

use super::{
    initialize_zk_prover_and_verifier, prover::StackedPcsZkProverContext,
    utils::compute_padding_amount, verifier::StackedPcsZkVerificationContext,
};

type GC = KoalaBearDegree4Duplex;
type MK = Poseidon2KoalaBear16Prover;

/// Data read from transcript that mirrors prover's commitment and eval claim.
struct PcsTranscriptData<Expr> {
    commitment_index: MleCommitmentIndex,
    eval_claim: Expr,
}

/// Reads proof data from the transcript for a single evaluation claim.
fn read_all<C: ZkCnstrAndReadingCtxInner<GC>>(
    context: &mut C,
    num_vars: usize,
    log_num_polys: usize,
) -> PcsTranscriptData<C::Expr> {
    let commitment_index = context
        .read_next_pcs_commitment(num_vars, log_num_polys)
        .expect("Failed to read PCS commitment");

    let eval_claim = context.read_one().expect("Failed to read eval claim");

    PcsTranscriptData { commitment_index, eval_claim }
}

/// Uniform constraint generation function (called by both prover and verifier).
/// Registers a single evaluation claim for the commitment.
fn build_all_constraints<C: ConstraintContextInnerExt<<GC as IopCtx>::EF>>(
    transcript_data: PcsTranscriptData<C::Expr>,
    point: &Point<<GC as IopCtx>::EF>,
    context: &mut C,
) {
    context.assert_mle_eval(
        transcript_data.commitment_index,
        point.clone(),
        transcript_data.eval_claim,
    );
}

/// Helper to run the full ZK stacked PCS prove-verify workflow with one claim.
fn run_zk_stacked_pcs_test(num_vars: u32, log_num_polys: u32, verbose: bool) {
    let mut rng = ChaCha20Rng::from_entropy();

    let total_num_vars = log_num_polys + num_vars;

    if verbose {
        eprintln!("Test configuration:");
        eprintln!("  Total variables: {}", total_num_vars);
        eprintln!("  Log stacking height: {}", log_num_polys);
        eprintln!("  Variables per column: {}", num_vars);
    }

    let original_mle = Mle::<<GC as IopCtx>::F>::rand(&mut rng, 1, total_num_vars);
    let eval_point = Point::<<GC as IopCtx>::EF>::rand(&mut rng, total_num_vars);
    let expected_eval = original_mle.eval_at(&eval_point);
    let expected_eval_value = expected_eval.evaluations().as_slice()[0];

    if verbose {
        eprintln!("  Expected evaluation: {:?}", expected_eval_value);
    }

    let (zk_basefold_prover, zk_stacked_verifier) =
        initialize_zk_prover_and_verifier::<GC, MK>(1, num_vars);

    let masks_length = compute_mask_length::<GC, _, _, _>(
        |ctx| read_all(ctx, num_vars as usize, log_num_polys as usize),
        |data, ctx| build_all_constraints(data, &eval_point, ctx),
    );

    // Prover Side
    let prover_start = std::time::Instant::now();
    let zkproof = {
        let mut prover_context: StackedPcsZkProverContext<GC, MK> =
            StackedPcsZkProverContext::initialize_only_lin_constraints(masks_length, &mut rng);

        let commitment_index = prover_context
            .commit_mle(original_mle.clone(), log_num_polys as usize, &zk_basefold_prover, &mut rng)
            .expect("Failed to commit MLEs");

        let claim = prover_context.add_value(expected_eval_value);

        let transcript_data = PcsTranscriptData { commitment_index, eval_claim: claim };
        build_all_constraints(transcript_data, &eval_point, &mut prover_context);

        prover_context.prove(&mut rng, Some(&zk_basefold_prover))
    };
    if verbose {
        eprintln!("Prover time: {:?}", prover_start.elapsed());
    }

    // Verifier Side
    let verifier_start = std::time::Instant::now();
    {
        let mut context: StackedPcsZkVerificationContext<GC> = zkproof.open();

        let transcript_data = read_all(&mut context, num_vars as usize, log_num_polys as usize);
        build_all_constraints(transcript_data, &eval_point, &mut context);

        context.verify(Some(&zk_stacked_verifier)).expect("Failed to verify proof");
    }
    if verbose {
        eprintln!("Verifier time: {:?}", verifier_start.elapsed());
    }
}

#[test]
fn test_zk_stacked_pcs_commit_and_prove() {
    eprintln!("\n=== ZK Stacked PCS Commit and Prove Test ===");
    run_zk_stacked_pcs_test(14, 8, true);
    eprintln!("\n=== TEST PASSED ===");
}

#[test]
fn test_zk_stacked_pcs_small_mle() {
    eprintln!("Testing with small MLE");
    run_zk_stacked_pcs_test(12, 6, true);
    eprintln!("Small MLE test PASSED");
}

#[test]
fn test_zk_stacked_pcs_large_mle() {
    eprintln!("Testing with large MLE");
    run_zk_stacked_pcs_test(20, 8, true);
    eprintln!("Large MLE test PASSED");
}

#[test]
fn test_compute_padding_amount() {
    let (zk_prover, _) = initialize_zk_prover_and_verifier::<GC, MK>(1, 16);

    let codeword_length = 1 << 16;
    let security_bits = 100;
    let inverse_rate = 1 << zk_prover.inner.encoder.config().log_blowup;
    let padding = compute_padding_amount(inverse_rate, codeword_length, security_bits).unwrap();
    eprintln!("Corrected computed padding amount: {}", padding);

    let inverse_rate = 1 << zk_prover.inner.encoder.config().log_blowup;
    let rho = (inverse_rate as f64).recip();
    let b = security_bits as f64;
    let lambda = -(0.5 + 0.5 * rho).log2();
    let out64 = b / lambda;
    let standard_padding = out64.ceil() as usize;
    eprintln!("Standard computed padding amount: {}", standard_padding);
}
