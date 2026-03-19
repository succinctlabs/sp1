#![allow(clippy::disallowed_types)]

use std::time::Instant;

use bincode::serialized_size;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use slop_algebra::AbstractField;
use slop_basefold::{BasefoldVerifier, FriConfig};
use slop_basefold_prover::BasefoldProver;
use slop_challenger::{CanObserve, IopCtx};
use slop_commit::Rounds;
use slop_koala_bear::KoalaBearDegree4Duplex;
use slop_matrix::dense::RowMajorMatrix;
use slop_merkle_tree::Poseidon2KoalaBear16Prover;
use slop_multilinear::{Mle, MultilinearPcsProver};
use slop_stacked::{StackedPcsProver, StackedPcsVerifier};
use slop_sumcheck::{partially_verify_sumcheck_proof, reduce_sumcheck_to_evaluation};
use slop_veil::builder::{
    compute_mask_length, ConstraintContextInnerExt, MleCommitmentIndex, ZkCnstrAndReadingCtxInner, ZkIopCtx,
    ZkProtocolParameters, ZkProtocolProof,
};
use slop_veil::stacked_pcs::{
    initialize_zk_prover_and_verifier, prover::StackedPcsZkProverContext,
    verifier::StackedPcsZkVerificationContext,
};

use slop_veil::example_zk_sumcheck::{
    verifier::ZkPartialSumcheckParameters, zk_reduce_sumcheck_to_evaluation, ZkPartialSumcheckProof,
};

/// Generates a random MLE and converts it for sumcheck.
///
/// Returns `(original_mle, mle_ef, claim)` where:
/// - `original_mle`: the random MLE in the base field
/// - `mle_ef`: extension field version for sumcheck
/// - `claim`: sum of all evaluations (the sumcheck claim)
fn generate_random_mle<GC: IopCtx>(
    rng: &mut impl rand::Rng,
    num_vars: u32,
) -> (Mle<GC::F>, Mle<GC::EF>, GC::EF)
where
    rand::distributions::Standard: rand::distributions::Distribution<GC::F>,
{
    let original_mle = Mle::<GC::F>::rand(rng, 1, num_vars);

    // Convert to extension field for sumcheck
    let ef_data: Vec<GC::EF> =
        original_mle.guts().as_slice().iter().map(|&x| GC::EF::from(x)).collect();
    let mle_ef = Mle::new(RowMajorMatrix::new(ef_data, 1).into());

    // Compute claim (sum of all evaluations)
    let claim: GC::EF = original_mle.guts().as_slice().iter().copied().sum::<GC::F>().into();

    (original_mle, mle_ef, claim)
}

/// Benchmarks ZK sumcheck + PCS eval vs standard sumcheck + PCS eval for a single MLE.
///
/// Both paths use the same random MLE with the same number of variables and the same
/// stacked PCS configuration. The only difference is the ZK overhead.
#[test]
fn benchmark_zk_vs_standard_sumcheck_with_pcs() {
    type GC = KoalaBearDegree4Duplex;
    type F = <GC as IopCtx>::F;
    type EF = <GC as IopCtx>::EF;

    // Configuration: match the ZK test's total variable count.
    const NUM_STACKED_VARS: u32 = 16;
    const LOG_STACKING_HEIGHT: u32 = 8;
    const TOTAL_NUM_VARS: u32 = LOG_STACKING_HEIGHT + NUM_STACKED_VARS;

    eprintln!("\n========================================");
    eprintln!("Benchmark: ZK vs Standard Sumcheck + PCS");
    eprintln!("  Total variables: {TOTAL_NUM_VARS}");
    eprintln!("  MLE size: 2^{TOTAL_NUM_VARS} = {}", 1u64 << TOTAL_NUM_VARS);
    eprintln!("  Stacking: log_height={LOG_STACKING_HEIGHT}, stacked_vars={NUM_STACKED_VARS}");
    eprintln!("========================================\n");

    let mut rng = ChaCha20Rng::from_entropy();
    let (original_mle, mle_ef, claim) = generate_random_mle::<GC>(&mut rng, TOTAL_NUM_VARS);
    let mle_ef_copy = mle_ef.clone();

    // ================================================================
    // STANDARD PATH: standard sumcheck + stacked PCS eval proof
    // ================================================================
    eprintln!("===== STANDARD SUMCHECK + STACKED PCS =====");

    let basefold_verifier = BasefoldVerifier::<GC>::new(FriConfig::default_fri_config(), 1);

    // --- Prover side ---
    let (commitment, sumcheck_proof, pcs_proof, standard_prover_time) = {
        let prover_start = Instant::now();

        let basefold_prover =
            BasefoldProver::<GC, Poseidon2KoalaBear16Prover>::new(&basefold_verifier);
        let batch_size = 1usize << LOG_STACKING_HEIGHT;
        let stacked_prover = StackedPcsProver::new(basefold_prover, NUM_STACKED_VARS, batch_size);

        // Commit the MLE via stacked PCS
        let commit_start = Instant::now();
        let mle_message = slop_commit::Message::from(vec![original_mle.clone()]);
        let (commitment, prover_data, _padding) =
            stacked_prover.commit_multilinears(mle_message).unwrap();
        eprintln!("  Commitment time:   {:?}", commit_start.elapsed());

        // Set up challenger and observe commitment
        let mut prover_challenger = GC::default_challenger();
        prover_challenger.observe(commitment);

        // Run standard sumcheck
        let sumcheck_start = Instant::now();
        let (sumcheck_proof, _component_evals) = reduce_sumcheck_to_evaluation::<F, EF, _>(
            vec![mle_ef],
            &mut prover_challenger,
            vec![claim],
            1,
            EF::one(),
        );
        eprintln!("  Sumcheck time:     {:?}", sumcheck_start.elapsed());

        // Prove PCS evaluation at the sumcheck's eval point
        let (eval_point, eval_claim) = sumcheck_proof.point_and_eval.clone();

        let pcs_start = Instant::now();
        let pcs_proof = stacked_prover
            .prove_trusted_evaluation(
                eval_point,
                eval_claim,
                Rounds { rounds: vec![prover_data] },
                &mut prover_challenger,
            )
            .unwrap();
        eprintln!("  PCS eval proof:    {:?}", pcs_start.elapsed());

        let prover_total = prover_start.elapsed();
        eprintln!("  PROVER TOTAL:      {:?}", prover_total);
        (commitment, sumcheck_proof, pcs_proof, prover_total)
    };

    // Measure standard proof size (everything except timing that left the prover scope)
    let fe = std::mem::size_of::<F>() as u64;
    let commitment_bytes = serialized_size(&commitment).unwrap();
    let sumcheck_bytes = serialized_size(&sumcheck_proof).unwrap();
    let pcs_bytes = serialized_size(&pcs_proof).unwrap();
    let standard_proof_bytes = commitment_bytes + sumcheck_bytes + pcs_bytes;
    let standard_proof_felts = standard_proof_bytes / fe;
    eprintln!("  Proof size:        {standard_proof_bytes} bytes ({standard_proof_felts} felts)");
    eprintln!("    commitment:      {commitment_bytes} bytes ({} felts)", commitment_bytes / fe);
    eprintln!("    sumcheck:        {sumcheck_bytes} bytes ({} felts)", sumcheck_bytes / fe);
    eprintln!("    pcs:             {pcs_bytes} bytes ({} felts)", pcs_bytes / fe);

    // --- Verifier side ---
    let standard_verifier_time = {
        let verifier_start = Instant::now();

        let stacked_verifier = StackedPcsVerifier::new(basefold_verifier, NUM_STACKED_VARS);

        let mut verifier_challenger = GC::default_challenger();
        verifier_challenger.observe(commitment);

        // Verify sumcheck
        let sumcheck_v_start = Instant::now();
        partially_verify_sumcheck_proof::<F, EF, _>(
            &sumcheck_proof,
            &mut verifier_challenger,
            TOTAL_NUM_VARS as usize,
            1,
        )
        .unwrap();
        eprintln!("  Sumcheck verify:   {:?}", sumcheck_v_start.elapsed());

        // Verify stacked PCS
        let (eval_point, eval_claim) = sumcheck_proof.point_and_eval.clone();
        let round_area = (1usize << TOTAL_NUM_VARS).next_multiple_of(1usize << NUM_STACKED_VARS);
        let pcs_v_start = Instant::now();
        stacked_verifier
            .verify_trusted_evaluation(
                &[commitment],
                &[round_area],
                &eval_point,
                &pcs_proof,
                eval_claim,
                &mut verifier_challenger,
            )
            .unwrap();
        eprintln!("  PCS verify:        {:?}", pcs_v_start.elapsed());

        let verifier_total = verifier_start.elapsed();
        eprintln!("  VERIFIER TOTAL:    {:?}", verifier_total);
        verifier_total
    };

    // ================================================================
    // ZK PATH: ZK sumcheck + ZK stacked PCS eval proof
    // ================================================================
    eprintln!("\n===== ZK SUMCHECK + ZK STACKED PCS =====");

    /// Reads all proof data from the transcript including PCS commitment.
    fn read_all<GC: ZkIopCtx, C: ZkCnstrAndReadingCtxInner<GC>>(
        context: &mut C,
    ) -> (MleCommitmentIndex, ZkPartialSumcheckProof<GC, C>) {
        let commitment_index = context
            .read_next_pcs_commitment(NUM_STACKED_VARS as usize, LOG_STACKING_HEIGHT as usize)
            .unwrap();
        let claimed_sum_index = context.read_one().unwrap();
        let sumcheck_data =
            ZkPartialSumcheckParameters::basic_sumcheck(TOTAL_NUM_VARS, claimed_sum_index)
                .read_proof_from_transcript(context)
                .unwrap();
        (commitment_index, sumcheck_data)
    }

    /// Uniform constraint generation function (called by both prover and verifier).
    fn build_all_constraints<GC: ZkIopCtx, C: ConstraintContextInnerExt<GC::EF>>(
        (commitment_index, sumcheck_data): (MleCommitmentIndex, ZkPartialSumcheckProof<GC, C>),
        ctx: &mut C,
    ) {
        ctx.assert_mle_eval(
            commitment_index,
            sumcheck_data.point.clone().into(),
            sumcheck_data.claimed_eval.clone(),
        );
        sumcheck_data.build_constraints();
    }

    let (zk_basefold_prover, zk_stacked_verifier) =
        initialize_zk_prover_and_verifier::<GC>(1, NUM_STACKED_VARS);

    // --- Prover side ---
    let (zkproof, zk_prover_time) = {
        let prover_start = Instant::now();

        let mask_count_start = Instant::now();
        let masks_length = compute_mask_length::<GC, _, _, _>(read_all, build_all_constraints);
        eprintln!(
            "  compute_mask_length: {:?} (masks_length={})",
            mask_count_start.elapsed(),
            masks_length
        );

        let init_start = Instant::now();
        let mut prover_context: StackedPcsZkProverContext<GC> =
            StackedPcsZkProverContext::initialize_only_lin_constraints(masks_length, &mut rng);
        eprintln!("  ZkProverContext::initialize: {:?}", init_start.elapsed());

        // Commit
        let commit_start = Instant::now();
        let commitment_index = prover_context
            .commit_mle(
                original_mle.clone(),
                LOG_STACKING_HEIGHT as usize,
                &zk_basefold_prover,
                &mut rng,
            )
            .expect("Failed to commit MLE");
        eprintln!("  Commitment time:   {:?}", commit_start.elapsed());

        // Run ZK sumcheck
        let sumcheck_start = Instant::now();
        let sum_claim = prover_context.add_value(claim);
        let (_, sumcheck_constraint_data) =
            zk_reduce_sumcheck_to_evaluation(mle_ef_copy, &mut prover_context, sum_claim);
        eprintln!("  Sumcheck time:     {:?}", sumcheck_start.elapsed());

        // Build constraints
        let cnstr_start = Instant::now();
        build_all_constraints((commitment_index, sumcheck_constraint_data), &mut prover_context);
        eprintln!("  build_constraints: {:?}", cnstr_start.elapsed());

        // Finalize ZK proof (includes PCS eval proof internally)
        let finalize_start = Instant::now();
        let zkproof = prover_context.prove(&mut rng, Some(&zk_basefold_prover));
        eprintln!("  Finalize (+ PCS):  {:?}", finalize_start.elapsed());

        let prover_total = prover_start.elapsed();
        eprintln!("  PROVER TOTAL:      {:?}", prover_total);
        (zkproof, prover_total)
    };

    // Measure ZK proof size (everything except timing that left the prover scope)
    let zk_proof_bytes = serialized_size(&zkproof).unwrap();
    let zk_proof_felts = zk_proof_bytes / fe;
    eprintln!("  Proof size:        {zk_proof_bytes} bytes ({zk_proof_felts} felts)");

    // --- Verifier side ---
    let zk_verifier_time = {
        let verifier_start = Instant::now();

        let open_start = Instant::now();
        let mut context: StackedPcsZkVerificationContext<GC> = zkproof.open();
        eprintln!("  open():            {:?}", open_start.elapsed());

        let read_start = Instant::now();
        let (commitment_index, sumcheck_data) = read_all::<GC, _>(&mut context);
        eprintln!("  read_all():        {:?}", read_start.elapsed());

        let cnstr_start = Instant::now();
        build_all_constraints((commitment_index, sumcheck_data), &mut context);
        eprintln!("  build_constraints: {:?}", cnstr_start.elapsed());

        let verify_start = Instant::now();
        context.verify(Some(&zk_stacked_verifier)).expect("Failed to verify");
        eprintln!("  verify():          {:?}", verify_start.elapsed());

        let verifier_total = verifier_start.elapsed();
        eprintln!("  VERIFIER TOTAL:    {:?}", verifier_total);
        verifier_total
    };

    // ================================================================
    // Summary
    // ================================================================
    eprintln!("\n===== SUMMARY =====");
    eprintln!(
        "  Standard prover:  {:?}  |  ZK prover:  {:?}  |  ZK overhead: {:.5}x",
        standard_prover_time,
        zk_prover_time,
        zk_prover_time.as_secs_f64() / standard_prover_time.as_secs_f64()
    );
    eprintln!(
        "  Standard verifier: {:?}  |  ZK verifier: {:?}  |  ZK overhead: {:.5}x",
        standard_verifier_time,
        zk_verifier_time,
        zk_verifier_time.as_secs_f64() / standard_verifier_time.as_secs_f64()
    );
    eprintln!(
        "  Standard proof:   {} felts  |  ZK proof:   {} felts  |  ZK overhead: {:.2}x",
        standard_proof_felts,
        zk_proof_felts,
        zk_proof_bytes as f64 / standard_proof_bytes as f64
    );
}
