#![allow(clippy::disallowed_types)]
use crate::zk::inner::{
    compute_mask_length, ConstraintContextInnerExt, MleCommitmentIndex, ZkCnstrAndReadingCtxInner,
    ZkIopCtx, ZkProtocolParameters, ZkProtocolProof,
};
use slop_merkle_tree::Poseidon2KoalaBear16Prover;

/// Default merkleizer used in tests (matches the concrete type for `KoalaBearDegree4Duplex`).
type MK = Poseidon2KoalaBear16Prover;
use crate::zk::stacked_pcs::{
    basefold_prover_wrapper::ZkBasefoldProver, initialize_zk_prover_and_verifier,
    prover::StackedPcsZkProverContext, verifier::StackedPcsZkVerificationContext,
    ZkStackedPcsVerifier,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use slop_challenger::{FieldChallenger, IopCtx};
use slop_jagged::{HadamardProduct, LongMle};
use slop_koala_bear::KoalaBearDegree4Duplex;
use slop_matrix::dense::RowMajorMatrix;
use slop_multilinear::Mle;

use super::{
    verifier::ZkPartialSumcheckParameters, zk_reduce_sumcheck_to_evaluation,
    zk_reduce_sumcheck_to_evaluation_general, ZkPartialSumcheckProof,
};

/// Generates a random MLE and converts it for sumcheck.
///
/// Returns `(original_mle, mle_ef, claim)` where:
/// - `original_mle`: the random MLE in the base field
/// - `mle_ef`: extension field version for sumcheck
/// - `claim`: sum of all evaluations (the sumcheck claim)
fn generate_random_mle<GC: IopCtx>(
    rng: &mut impl Rng,
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

/// Generates two random MLEs and prepares a Hadamard product for sumcheck.
///
/// Returns `(original_mle_1, original_mle_2, hadamard_product, claim)` where:
/// - `original_mle_1`, `original_mle_2`: the random MLEs in the base field
/// - `hadamard_product`: the element-wise product for sumcheck
/// - `claim`: sum of all Hadamard product evaluations (the sumcheck claim)
#[allow(clippy::type_complexity)]
fn generate_random_hadamard_product<GC: IopCtx>(
    rng: &mut impl Rng,
    num_vars: u32,
) -> (Mle<GC::F>, Mle<GC::F>, HadamardProduct<GC::F, GC::EF>, GC::EF)
where
    rand::distributions::Standard: rand::distributions::Distribution<GC::F>,
{
    let original_mle_1 = Mle::<GC::F>::rand(rng, 1, num_vars);
    let original_mle_2 = Mle::<GC::F>::rand(rng, 1, num_vars);

    // Build Hadamard product (base stays in F, ext is converted to EF)
    let long_base = LongMle::from_components(vec![original_mle_1.clone()], num_vars);
    let mle_2_ef_data: Vec<GC::EF> =
        original_mle_2.guts().as_slice().iter().map(|&x| GC::EF::from(x)).collect();
    let mle_2_as_ef = Mle::new(RowMajorMatrix::new(mle_2_ef_data, 1).into());
    let long_ext = LongMle::from_components(vec![mle_2_as_ef], num_vars);
    let product = HadamardProduct { base: long_base, ext: long_ext };

    // Compute claim (sum of element-wise products)
    let claim: GC::EF = original_mle_1
        .guts()
        .as_slice()
        .iter()
        .zip(original_mle_2.guts().as_slice().iter())
        .map(|(&b, &e)| GC::EF::from(b) * GC::EF::from(e))
        .sum();

    (original_mle_1, original_mle_2, product, claim)
}

#[test]
fn test_zk_sumcheck() {
    let mut rng = ChaCha20Rng::from_entropy();

    type GC = KoalaBearDegree4Duplex;

    const NUM_VARIABLES: u32 = 16;

    /// Reads all proof data from the transcript.
    /// Returns the data needed for `build_all_constraints`.
    fn read_all<GC: ZkIopCtx, C: ZkCnstrAndReadingCtxInner<GC>>(
        context: &mut C,
    ) -> ZkPartialSumcheckProof<GC, C> {
        // Read the index of the claimed sum value
        let claimed_sum_index = context.read_one().unwrap();

        // Read proof from transcript (reconstructs Fiat-Shamir state)

        ZkPartialSumcheckParameters::basic_hadamard_sumcheck(NUM_VARIABLES, claimed_sum_index)
            .read_proof_from_transcript(context)
            .unwrap()
    }

    // Uniform constraint generation function (called by both prover and verifier)
    // Generic over the context type C to work with both ZkProverContext and ZkVerificationContext.
    fn build_all_constraints<GC: ZkIopCtx, C: ConstraintContextInnerExt<GC::EF>>(
        sumcheck_data: ZkPartialSumcheckProof<GC, C>,
        _ctx: &mut C,
    ) {
        sumcheck_data.build_constraints()
    }

    // Test data
    let (_, _, product, claim_value) =
        generate_random_hadamard_product::<GC>(&mut rng, NUM_VARIABLES);

    // Prover Side
    eprintln!("Prover-side for ZK Sumcheck test");
    let zkproof = {
        let now = std::time::Instant::now();

        // Starting the ZK proof
        let masks_length = compute_mask_length::<GC, _, _, _>(read_all, build_all_constraints);
        let mut prover_context: StackedPcsZkProverContext<GC, MK> =
            StackedPcsZkProverContext::initialize_only_lin_constraints(masks_length, &mut rng);

        // Generating sumcheck proof
        let claim = prover_context.add_value(claim_value);

        let (_, sumcheck_constraint_data) =
            zk_reduce_sumcheck_to_evaluation(product, &mut prover_context, claim);

        // Add constraints using uniform function
        build_all_constraints(sumcheck_constraint_data, &mut prover_context);

        // Finalizing the ZK proof (no PCS used in this test)
        let zkproof = prover_context.prove(&mut rng, None::<&ZkBasefoldProver<GC, MK>>);
        eprintln!("Total prover time {:?}\n", now.elapsed());
        zkproof
    };

    // Verifier Side
    eprintln!("Verifier-side for ZK Sumcheck test");
    {
        let now = std::time::Instant::now();

        // Open the zk proof
        let mut context: StackedPcsZkVerificationContext<GC> = zkproof.open();

        // Read all proof data from transcript
        let sumcheck_data = read_all::<GC, _>(&mut context);

        // Build constraints
        build_all_constraints(sumcheck_data, &mut context);

        // Verify (no PCS used, but need to specify verifier type)
        context.verify::<ZkStackedPcsVerifier<GC>>(None).unwrap();
        eprintln!("Verification time {:?}", now.elapsed());
    }
}

#[test]
fn test_zk_sumcheck_with_pcs_eval_proof_single_mle() {
    // Test that generates a single random MLE, commits it, does zk-sumcheck on it,
    // and zk-proves the evaluation claim sumcheck produces

    let mut rng = ChaCha20Rng::from_entropy();

    type GC = KoalaBearDegree4Duplex;

    // Configuration parameters
    const NUM_ENCODING_VARIABLES: u32 = 16; // Width / number of variables per stacked polynomial
    const LOG_NUM_POLYNOMIALS: u32 = 8; // Stacking height / number of columns
    const NUM_VARIABLES: u32 = LOG_NUM_POLYNOMIALS + NUM_ENCODING_VARIABLES;

    eprintln!("Test configuration:");
    eprintln!("  Total variables: {}", NUM_VARIABLES);
    eprintln!("  Log num polynomials: {}", LOG_NUM_POLYNOMIALS);
    eprintln!("  Log encoding vars: {}", NUM_ENCODING_VARIABLES);

    /// Reads all proof data from the transcript including PCS commitment.
    fn read_all<GC: ZkIopCtx, C: ZkCnstrAndReadingCtxInner<GC>>(
        context: &mut C,
    ) -> (MleCommitmentIndex, ZkPartialSumcheckProof<GC, C>) {
        // Read PCS commitment
        let commitment_index = context
            .read_next_pcs_commitment(NUM_ENCODING_VARIABLES as usize, LOG_NUM_POLYNOMIALS as usize)
            .unwrap();

        // Read claimed sum
        let claimed_sum_index = context.read_one().unwrap();

        // Read sumcheck proof
        let sumcheck_data =
            ZkPartialSumcheckParameters::basic_sumcheck(NUM_VARIABLES, claimed_sum_index)
                .read_proof_from_transcript(context)
                .unwrap();

        (commitment_index, sumcheck_data)
    }

    /// Uniform constraint generation function (called by both prover and verifier).
    fn build_all_constraints<GC: ZkIopCtx, C: ConstraintContextInnerExt<GC::EF>>(
        (commitment_index, sumcheck_data): (MleCommitmentIndex, ZkPartialSumcheckProof<GC, C>),
        ctx: &mut C,
    ) {
        // Add PCS eval claim
        ctx.assert_mle_eval(
            commitment_index,
            sumcheck_data.point.clone().into(),
            sumcheck_data.claimed_eval.clone(),
        );

        // Build sumcheck constraints
        sumcheck_data.build_constraints();
    }

    // Generate test data
    let (original_mle, mle_ef, claim) = generate_random_mle::<GC>(&mut rng, NUM_VARIABLES);

    eprintln!("  Sumcheck claim (sum of all evals): {:?}", claim);

    // Initialize the verifiers and provers for PCS
    let (zk_basefold_prover, zk_stacked_verifier) =
        initialize_zk_prover_and_verifier::<GC, MK>(1, NUM_ENCODING_VARIABLES);

    //
    // Prover Side
    //
    eprintln!("\n=== PROVER SIDE ===");
    let zkproof = {
        let prover_start = std::time::Instant::now();

        // Initialize the zkbuilder
        let masks_length = compute_mask_length::<GC, _, _, _>(read_all, build_all_constraints);
        let mut prover_context: StackedPcsZkProverContext<GC, MK> =
            StackedPcsZkProverContext::initialize_only_lin_constraints(masks_length, &mut rng);

        eprintln!("Committing MLE...");
        let commit_start = std::time::Instant::now();
        let commitment_index = prover_context
            .commit_mle(original_mle, LOG_NUM_POLYNOMIALS as usize, &zk_basefold_prover, &mut rng)
            .expect("Failed to commit MLEs");
        eprintln!("  Commitment time: {:?}", commit_start.elapsed());

        // Run zk-sumcheck on the MLE
        eprintln!("Running zk-sumcheck...");
        let sumcheck_start = std::time::Instant::now();
        // Write claimed eval to zkbuilder
        let sum_claim = prover_context.add_value(claim);
        // Run the sumcheck (returns output and constraint data separately)
        let (_, sumcheck_constraint_data) =
            zk_reduce_sumcheck_to_evaluation(mle_ef, &mut prover_context, sum_claim);
        eprintln!("  Sumcheck time: {:?}", sumcheck_start.elapsed());

        // Build all constraints using uniform function (registers PCS eval claim)
        build_all_constraints((commitment_index, sumcheck_constraint_data), &mut prover_context);

        // Finalize the ZK proof (PCS proofs generated internally)
        eprintln!("Finalizing ZK proof...");
        let finalize_start = std::time::Instant::now();
        let zkproof = prover_context.prove(&mut rng, Some(&zk_basefold_prover));
        eprintln!("  Finalization time: {:?}", finalize_start.elapsed());
        eprintln!("Total prover time: {:?}", prover_start.elapsed());

        zkproof
    };

    //
    // Verifier Side
    //
    eprintln!("\n=== VERIFIER SIDE ===");
    {
        let verifier_start = std::time::Instant::now();

        // Open the handler into a context
        let mut context: StackedPcsZkVerificationContext<GC> = zkproof.open();

        // Read all proof data from transcript
        let (commitment_index, sumcheck_data) = read_all::<GC, _>(&mut context);

        // Build constraints using uniform function
        build_all_constraints((commitment_index, sumcheck_data), &mut context);

        // Finalize the ZK proof verification (PCS proofs verified internally)
        eprintln!("Finalizing ZK proof verification...");
        let verify_final_start = std::time::Instant::now();
        context.verify(Some(&zk_stacked_verifier)).expect("Failed to verify constraints");
        eprintln!("  Final verification time: {:?}", verify_final_start.elapsed());
        eprintln!("Total verifier time: {:?}", verifier_start.elapsed());
    }

    eprintln!("\n=== TEST PASSED ===");
}

#[test]
fn test_zk_sumcheck_with_pcs_eval_proof_hadamard_product() {
    // Test that generates two random MLEs, commits them both, does zk-sumcheck on their
    // Hadamard product, and zk-proves the evaluation claims using multiplicative constraints

    let mut rng = ChaCha20Rng::from_entropy();

    type GC = KoalaBearDegree4Duplex;

    // Configuration parameters
    const NUM_ENCODING_VARIABLES: u32 = 16; // Width / number of variables per stacked polynomial
    const LOG_NUM_POLYNOMIALS: u32 = 8; // Stacking height / number of columns
    const NUM_VARIABLES: u32 = LOG_NUM_POLYNOMIALS + NUM_ENCODING_VARIABLES;

    eprintln!("Test configuration:");
    eprintln!("  Total variables: {}", NUM_VARIABLES);
    eprintln!("  Log num polynomials: {}", LOG_NUM_POLYNOMIALS);
    eprintln!("  Log encoding vars: {}", NUM_ENCODING_VARIABLES);

    /// Reads all proof data from the transcript including both PCS commitments.
    fn read_all<GC: ZkIopCtx, C: ZkCnstrAndReadingCtxInner<GC>>(
        context: &mut C,
    ) -> (MleCommitmentIndex, MleCommitmentIndex, ZkPartialSumcheckProof<GC, C>) {
        // Read both PCS commitments
        let commitment_index_base = context
            .read_next_pcs_commitment(NUM_ENCODING_VARIABLES as usize, LOG_NUM_POLYNOMIALS as usize)
            .unwrap();
        let commitment_index_ext = context
            .read_next_pcs_commitment(NUM_ENCODING_VARIABLES as usize, LOG_NUM_POLYNOMIALS as usize)
            .unwrap();

        // Read claimed sum
        let claimed_sum_index = context.read_one().unwrap();

        // Read sumcheck proof
        let sumcheck_data =
            ZkPartialSumcheckParameters::basic_hadamard_sumcheck(NUM_VARIABLES, claimed_sum_index)
                .read_proof_from_transcript(context)
                .unwrap();

        (commitment_index_base, commitment_index_ext, sumcheck_data)
    }

    /// Uniform constraint generation function (called by both prover and verifier).
    fn build_all_constraints<GC: ZkIopCtx, C: ConstraintContextInnerExt<GC::EF>>(
        (commitment_index_base, commitment_index_ext, sumcheck_data): (
            MleCommitmentIndex,
            MleCommitmentIndex,
            ZkPartialSumcheckProof<GC, C>,
        ),
        ctx: &mut C,
    ) {
        // Multiplicative constraint: base_eval * ext_eval = total_eval
        // The component_poly_evals[0] contains [base_eval, ext_eval]
        let base_eval = sumcheck_data.component_poly_evals[0][0].clone();
        let ext_eval = sumcheck_data.component_poly_evals[0][1].clone();
        ctx.assert_a_times_b_equals_c(
            base_eval.clone(),
            ext_eval.clone(),
            sumcheck_data.claimed_eval.clone(),
        );

        // Add PCS eval claims for both MLEs
        ctx.assert_mle_eval(commitment_index_base, sumcheck_data.point.clone().into(), base_eval);
        ctx.assert_mle_eval(commitment_index_ext, sumcheck_data.point.clone().into(), ext_eval);

        // Build sumcheck constraints
        sumcheck_data.build_constraints();
    }

    // Generate test data
    let (original_mle_1, original_mle_2, hadamard_product, claim) =
        generate_random_hadamard_product::<GC>(&mut rng, NUM_VARIABLES);

    eprintln!("  Sumcheck claim (sum of Hadamard product): {:?}", claim);

    // Initialize the verifiers and provers for PCS
    let (zk_basefold_prover, zk_stacked_verifier) =
        initialize_zk_prover_and_verifier::<GC, MK>(1, NUM_ENCODING_VARIABLES);

    //
    // Prover Side
    //
    eprintln!("\n=== PROVER SIDE ===");
    let zkproof = {
        let prover_start = std::time::Instant::now();

        // Initialize the zkbuilder with multiplicative constraint support
        let masks_length = compute_mask_length::<GC, _, _, _>(read_all, build_all_constraints);
        let mut prover_context: StackedPcsZkProverContext<GC, MK> =
            StackedPcsZkProverContext::initialize(masks_length, &mut rng);

        eprintln!("Committing MLEs...");
        let commit_start = std::time::Instant::now();
        // Commit base MLE
        let commitment_index_base = prover_context
            .commit_mle(original_mle_1, LOG_NUM_POLYNOMIALS as usize, &zk_basefold_prover, &mut rng)
            .expect("Failed to commit base MLE");
        // Commit ext MLE
        let commitment_index_ext = prover_context
            .commit_mle(original_mle_2, LOG_NUM_POLYNOMIALS as usize, &zk_basefold_prover, &mut rng)
            .expect("Failed to commit ext MLE");
        eprintln!("  Commitment time: {:?}", commit_start.elapsed());

        // Run zk-sumcheck on the Hadamard product
        eprintln!("Running zk-sumcheck on Hadamard product...");
        let sumcheck_start = std::time::Instant::now();
        // Write claimed eval to proof transcript
        let sum_claim = prover_context.add_value(claim);
        // Run the sumcheck (returns output and constraint data separately)
        let (_, sumcheck_constraint_data) =
            zk_reduce_sumcheck_to_evaluation(hadamard_product, &mut prover_context, sum_claim);
        eprintln!("  Sumcheck time: {:?}", sumcheck_start.elapsed());

        // Add constraints using uniform function
        build_all_constraints(
            (commitment_index_base, commitment_index_ext, sumcheck_constraint_data),
            &mut prover_context,
        );

        // Finalize the ZK proof (PCS proofs generated internally)
        eprintln!("Finalizing ZK proof...");
        let finalize_start = std::time::Instant::now();
        let zkproof = prover_context.prove(&mut rng, Some(&zk_basefold_prover));
        eprintln!("  Finalization time: {:?}", finalize_start.elapsed());
        eprintln!("Total prover time: {:?}", prover_start.elapsed());
        zkproof
    };

    //
    // Verifier Side
    //
    eprintln!("\n=== VERIFIER SIDE ===");
    {
        let verifier_start = std::time::Instant::now();

        // Unwrap the ZK proof
        let mut context: StackedPcsZkVerificationContext<GC> = zkproof.open();

        // Read all proof data from transcript
        let (commitment_index_base, commitment_index_ext, sumcheck_data) =
            read_all::<GC, _>(&mut context);

        // Build constraints using uniform function
        build_all_constraints(
            (commitment_index_base, commitment_index_ext, sumcheck_data),
            &mut context,
        );

        // Finalize the ZK proof verification (PCS proofs verified internally)
        eprintln!("Finalizing ZK proof verification...");
        let verify_final_start = std::time::Instant::now();
        context.verify(Some(&zk_stacked_verifier)).expect("Failed to verify constraints");
        eprintln!("  Final verification time: {:?}", verify_final_start.elapsed());
        eprintln!("Total verifier time: {:?}", verifier_start.elapsed());
    }

    eprintln!("\n=== TEST PASSED ===");
}

#[test]
fn test_zk_sumcheck_with_pcs_eval_proof_batched_single_mles() {
    // Test that generates multiple random MLEs, commits them, batches their sumcheck claims
    // using zk_reduce_sumcheck_to_evaluation_general with an RLC coefficient lambda sampled
    // from the challenger, and zk-proves the resulting PCS evaluation claims.

    let mut rng = ChaCha20Rng::from_entropy();

    type GC = KoalaBearDegree4Duplex;
    type EF = <GC as IopCtx>::EF;

    // Configuration parameters
    const NUM_CLAIMS: usize = 3;
    const NUM_ENCODING_VARIABLES: u32 = 16;
    const LOG_NUM_POLYNOMIALS: u32 = 8;
    const NUM_VARIABLES: u32 = LOG_NUM_POLYNOMIALS + NUM_ENCODING_VARIABLES;

    eprintln!("Test configuration:");
    eprintln!("  Num claims: {}", NUM_CLAIMS);
    eprintln!("  Total variables: {}", NUM_VARIABLES);
    eprintln!("  Log num polynomials: {}", LOG_NUM_POLYNOMIALS);
    eprintln!("  Log encoding vars: {}", NUM_ENCODING_VARIABLES);

    /// Reads all proof data from the transcript including PCS commitments and lambda.
    fn read_all<GC: ZkIopCtx, C: ZkCnstrAndReadingCtxInner<GC>>(
        context: &mut C,
    ) -> (Vec<MleCommitmentIndex>, ZkPartialSumcheckProof<GC, C>) {
        // Read PCS commitments
        let commitment_indices: Vec<_> = (0..NUM_CLAIMS)
            .map(|_| {
                context
                    .read_next_pcs_commitment(
                        NUM_ENCODING_VARIABLES as usize,
                        LOG_NUM_POLYNOMIALS as usize,
                    )
                    .unwrap()
            })
            .collect();

        // Read claimed sums
        let claimed_sum_indices: Vec<_> =
            (0..NUM_CLAIMS).map(|_| context.read_one().unwrap()).collect();

        // Sample RLC coefficient lambda from challenger
        let lambda: GC::EF = context.challenger().sample_ext_element();

        // Read sumcheck proof
        let sumcheck_data = ZkPartialSumcheckParameters {
            num_variables: NUM_VARIABLES,
            degree: 1,
            poly_component_counts: vec![1; NUM_CLAIMS],
            claim_exprs: claimed_sum_indices,
            lambda,
            t: 1,
        }
        .read_proof_from_transcript(context)
        .unwrap();

        (commitment_indices, sumcheck_data)
    }

    /// Uniform constraint generation function (called by both prover and verifier).
    fn build_all_constraints<GC: ZkIopCtx, C: ConstraintContextInnerExt<GC::EF>>(
        (commitment_indices, sumcheck_data): (
            Vec<MleCommitmentIndex>,
            ZkPartialSumcheckProof<GC, C>,
        ),
        ctx: &mut C,
    ) {
        // Add PCS eval claims for each MLE
        for (i, commitment_index) in commitment_indices.iter().enumerate() {
            ctx.assert_mle_eval(
                *commitment_index,
                sumcheck_data.point.clone().into(),
                sumcheck_data.component_poly_evals[i][0].clone(),
            );
        }

        // Build sumcheck constraints
        sumcheck_data.build_constraints();
    }

    // Generate test data
    let mut flat_mles = Vec::new();
    let mut mles_ef = Vec::new();
    let mut claims = Vec::new();
    for _ in 0..NUM_CLAIMS {
        let (original, ef, claim) = generate_random_mle::<GC>(&mut rng, NUM_VARIABLES);
        flat_mles.push(original);
        mles_ef.push(ef);
        claims.push(claim);
    }

    for (i, claim) in claims.iter().enumerate() {
        eprintln!("  Sumcheck claim {} (sum of all evals): {:?}", i, claim);
    }

    // Initialize PCS prover and verifier
    let (zk_basefold_prover, zk_stacked_verifier) =
        initialize_zk_prover_and_verifier::<GC, MK>(1, NUM_ENCODING_VARIABLES);

    //
    // Prover Side
    //
    eprintln!("\n=== PROVER SIDE ===");
    let zkproof = {
        let prover_start = std::time::Instant::now();

        let masks_length = compute_mask_length::<GC, _, _, _>(read_all, build_all_constraints);
        let mut prover_context: StackedPcsZkProverContext<GC, MK> =
            StackedPcsZkProverContext::initialize_only_lin_constraints(masks_length, &mut rng);

        // Commit all MLEs
        eprintln!("Committing MLEs...");
        let commit_start = std::time::Instant::now();
        let commitment_indices: Vec<_> = flat_mles
            .into_iter()
            .map(|flat_mle| {
                prover_context
                    .commit_mle(
                        flat_mle,
                        LOG_NUM_POLYNOMIALS as usize,
                        &zk_basefold_prover,
                        &mut rng,
                    )
                    .expect("Failed to commit MLE")
            })
            .collect();
        eprintln!("  Commitment time: {:?}", commit_start.elapsed());

        // Add claim values to prover context
        let claim_values: Vec<_> =
            claims.iter().map(|&claim| prover_context.add_value(claim)).collect();

        // Sample RLC coefficient lambda from challenger
        let lambda: EF = prover_context.challenger().sample_ext_element();

        // Run batched zk-sumcheck
        eprintln!("Running batched zk-sumcheck...");
        let sumcheck_start = std::time::Instant::now();
        let (_, sumcheck_constraint_data) = zk_reduce_sumcheck_to_evaluation_general(
            mles_ef,
            &mut prover_context,
            claim_values,
            1,
            lambda,
        );
        eprintln!("  Sumcheck time: {:?}", sumcheck_start.elapsed());

        // Build constraints
        build_all_constraints((commitment_indices, sumcheck_constraint_data), &mut prover_context);

        // Finalize ZK proof
        eprintln!("Finalizing ZK proof...");
        let finalize_start = std::time::Instant::now();
        let zkproof = prover_context.prove(&mut rng, Some(&zk_basefold_prover));
        eprintln!("  Finalization time: {:?}", finalize_start.elapsed());
        eprintln!("Total prover time: {:?}", prover_start.elapsed());
        zkproof
    };

    //
    // Verifier Side
    //
    eprintln!("\n=== VERIFIER SIDE ===");
    {
        let verifier_start = std::time::Instant::now();

        let mut context: StackedPcsZkVerificationContext<GC> = zkproof.open();

        // Read all proof data from transcript
        let (commitment_indices, sumcheck_data) = read_all::<GC, _>(&mut context);

        // Build constraints
        build_all_constraints((commitment_indices, sumcheck_data), &mut context);

        // Verify
        eprintln!("Finalizing ZK proof verification...");
        let verify_final_start = std::time::Instant::now();
        context.verify(Some(&zk_stacked_verifier)).expect("Failed to verify constraints");
        eprintln!("  Final verification time: {:?}", verify_final_start.elapsed());
        eprintln!("Total verifier time: {:?}", verifier_start.elapsed());
    }

    eprintln!("\n=== TEST PASSED ===");
}

#[test]
#[should_panic(expected = "Multiple eval claims on the same PCS commitment")]
fn test_zk_sumcheck_triple_hadamard_with_batched_pcs() {
    // Test that generates three random MLEs f, g, h, commits them, runs three separate
    // hadamard sumchecks (fg, gh, hf), producing two evaluation claims per commitment
    // at different points. This exercises the batched multi-point PCS evaluation feature:
    //   f gets eval claims at p1 (from fg) and p3 (from hf)
    //   g gets eval claims at p1 (from fg) and p2 (from gh)
    //   h gets eval claims at p2 (from gh) and p3 (from hf)

    let mut rng = ChaCha20Rng::from_entropy();

    type GC = KoalaBearDegree4Duplex;

    const NUM_ENCODING_VARIABLES: u32 = 12;
    const LOG_NUM_POLYNOMIALS: u32 = 6;
    const NUM_VARIABLES: u32 = LOG_NUM_POLYNOMIALS + NUM_ENCODING_VARIABLES;

    eprintln!("Test configuration:");
    eprintln!("  Total variables: {}", NUM_VARIABLES);
    eprintln!("  Log num polynomials: {}", LOG_NUM_POLYNOMIALS);
    eprintln!("  Log encoding vars: {}", NUM_ENCODING_VARIABLES);

    /// Reads all proof data from the transcript: three PCS commitments and three
    /// hadamard sumcheck proofs (fg, gh, hf).
    fn read_all<GC: ZkIopCtx, C: ZkCnstrAndReadingCtxInner<GC>>(
        context: &mut C,
    ) -> ([MleCommitmentIndex; 3], [ZkPartialSumcheckProof<GC, C>; 3]) {
        let commitment_f = context
            .read_next_pcs_commitment(NUM_ENCODING_VARIABLES as usize, LOG_NUM_POLYNOMIALS as usize)
            .unwrap();
        let commitment_g = context
            .read_next_pcs_commitment(NUM_ENCODING_VARIABLES as usize, LOG_NUM_POLYNOMIALS as usize)
            .unwrap();
        let commitment_h = context
            .read_next_pcs_commitment(NUM_ENCODING_VARIABLES as usize, LOG_NUM_POLYNOMIALS as usize)
            .unwrap();

        let read_sumcheck = |ctx: &mut C| {
            let claimed_sum = ctx.read_one().unwrap();
            ZkPartialSumcheckParameters::basic_hadamard_sumcheck(NUM_VARIABLES, claimed_sum)
                .read_proof_from_transcript(ctx)
                .unwrap()
        };
        let sumcheck_fg = read_sumcheck(context);
        let sumcheck_gh = read_sumcheck(context);
        let sumcheck_hf = read_sumcheck(context);

        ([commitment_f, commitment_g, commitment_h], [sumcheck_fg, sumcheck_gh, sumcheck_hf])
    }

    /// Uniform constraint generation function (called by both prover and verifier).
    fn build_all_constraints<GC: ZkIopCtx, C: ConstraintContextInnerExt<GC::EF>>(
        (commitments, sumchecks): ([MleCommitmentIndex; 3], [ZkPartialSumcheckProof<GC, C>; 3]),
        ctx: &mut C,
    ) {
        let [commitment_f, commitment_g, commitment_h] = commitments;
        let [sumcheck_fg, sumcheck_gh, sumcheck_hf] = sumchecks;

        // Extract component evaluations and points before consuming proofs
        // fg product: component_poly_evals[0] = [f(p1), g(p1)]
        let f_at_p1 = sumcheck_fg.component_poly_evals[0][0].clone();
        let g_at_p1 = sumcheck_fg.component_poly_evals[0][1].clone();
        let point_p1 = sumcheck_fg.point.clone();
        let claimed_eval_fg = sumcheck_fg.claimed_eval.clone();

        // gh product: component_poly_evals[0] = [g(p2), h(p2)]
        let g_at_p2 = sumcheck_gh.component_poly_evals[0][0].clone();
        let h_at_p2 = sumcheck_gh.component_poly_evals[0][1].clone();
        let point_p2 = sumcheck_gh.point.clone();
        let claimed_eval_gh = sumcheck_gh.claimed_eval.clone();

        // hf product: component_poly_evals[0] = [h(p3), f(p3)]
        let h_at_p3 = sumcheck_hf.component_poly_evals[0][0].clone();
        let f_at_p3 = sumcheck_hf.component_poly_evals[0][1].clone();
        let point_p3 = sumcheck_hf.point.clone();
        let claimed_eval_hf = sumcheck_hf.claimed_eval.clone();

        // Multiplicative constraints: base * ext = claimed_eval
        ctx.assert_a_times_b_equals_c(f_at_p1.clone(), g_at_p1.clone(), claimed_eval_fg);
        ctx.assert_a_times_b_equals_c(g_at_p2.clone(), h_at_p2.clone(), claimed_eval_gh);
        ctx.assert_a_times_b_equals_c(h_at_p3.clone(), f_at_p3.clone(), claimed_eval_hf);

        // PCS eval claims: two per commitment at different points
        // f: claims at p1 (from fg) and p3 (from hf)
        ctx.assert_mle_eval(commitment_f, point_p1.clone().into(), f_at_p1);
        ctx.assert_mle_eval(commitment_f, point_p3.clone().into(), f_at_p3);

        // g: claims at p1 (from fg) and p2 (from gh)
        ctx.assert_mle_eval(commitment_g, point_p1.into(), g_at_p1);
        ctx.assert_mle_eval(commitment_g, point_p2.clone().into(), g_at_p2);

        // h: claims at p2 (from gh) and p3 (from hf)
        ctx.assert_mle_eval(commitment_h, point_p2.into(), h_at_p2);
        ctx.assert_mle_eval(commitment_h, point_p3.into(), h_at_p3);

        // Build sumcheck constraints
        sumcheck_fg.build_constraints();
        sumcheck_gh.build_constraints();
        sumcheck_hf.build_constraints();
    }

    // Generate three random MLEs
    let mle_f = Mle::<<GC as IopCtx>::F>::rand(&mut rng, 1, NUM_VARIABLES);
    let mle_g = Mle::<<GC as IopCtx>::F>::rand(&mut rng, 1, NUM_VARIABLES);
    let mle_h = Mle::<<GC as IopCtx>::F>::rand(&mut rng, 1, NUM_VARIABLES);

    // Build Hadamard products and compute claims
    let build_hadamard =
        |base: &Mle<<GC as IopCtx>::F>, ext: &Mle<<GC as IopCtx>::F>| -> HadamardProduct<_, _> {
            let long_base = LongMle::from_components(vec![base.clone()], NUM_VARIABLES);
            let ext_ef_data: Vec<<GC as IopCtx>::EF> =
                ext.guts().as_slice().iter().map(|&x| x.into()).collect();
            let ext_as_ef = Mle::new(RowMajorMatrix::new(ext_ef_data, 1).into());
            let long_ext = LongMle::from_components(vec![ext_as_ef], NUM_VARIABLES);
            HadamardProduct { base: long_base, ext: long_ext }
        };

    let compute_claim =
        |a: &Mle<<GC as IopCtx>::F>, b: &Mle<<GC as IopCtx>::F>| -> <GC as IopCtx>::EF {
            a.guts()
                .as_slice()
                .iter()
                .zip(b.guts().as_slice().iter())
                .map(|(&x, &y)| <GC as IopCtx>::EF::from(x) * <GC as IopCtx>::EF::from(y))
                .sum()
        };

    let product_fg = build_hadamard(&mle_f, &mle_g);
    let product_gh = build_hadamard(&mle_g, &mle_h);
    let product_hf = build_hadamard(&mle_h, &mle_f);

    let claim_fg = compute_claim(&mle_f, &mle_g);
    let claim_gh = compute_claim(&mle_g, &mle_h);
    let claim_hf = compute_claim(&mle_h, &mle_f);

    eprintln!("  Claim fg: {:?}", claim_fg);
    eprintln!("  Claim gh: {:?}", claim_gh);
    eprintln!("  Claim hf: {:?}", claim_hf);

    let (zk_basefold_prover, zk_stacked_verifier) =
        initialize_zk_prover_and_verifier::<GC, MK>(1, NUM_ENCODING_VARIABLES);

    //
    // Prover Side
    //
    eprintln!("\n=== PROVER SIDE ===");
    let zkproof = {
        let prover_start = std::time::Instant::now();

        let masks_length = compute_mask_length::<GC, _, _, _>(read_all, build_all_constraints);
        let mut prover_context: StackedPcsZkProverContext<GC, MK> =
            StackedPcsZkProverContext::initialize(masks_length, &mut rng);

        // Commit f, g, h
        eprintln!("Committing MLEs...");
        let commit_start = std::time::Instant::now();
        let commitment_f = prover_context
            .commit_mle(mle_f, LOG_NUM_POLYNOMIALS as usize, &zk_basefold_prover, &mut rng)
            .expect("Failed to commit f");
        let commitment_g = prover_context
            .commit_mle(mle_g, LOG_NUM_POLYNOMIALS as usize, &zk_basefold_prover, &mut rng)
            .expect("Failed to commit g");
        let commitment_h = prover_context
            .commit_mle(mle_h, LOG_NUM_POLYNOMIALS as usize, &zk_basefold_prover, &mut rng)
            .expect("Failed to commit h");
        eprintln!("  Commitment time: {:?}", commit_start.elapsed());

        // Run three separate hadamard sumchecks
        eprintln!("Running hadamard sumchecks...");
        let sumcheck_start = std::time::Instant::now();

        let claim_fg_expr = prover_context.add_value(claim_fg);
        let (_, data_fg) =
            zk_reduce_sumcheck_to_evaluation(product_fg, &mut prover_context, claim_fg_expr);

        let claim_gh_expr = prover_context.add_value(claim_gh);
        let (_, data_gh) =
            zk_reduce_sumcheck_to_evaluation(product_gh, &mut prover_context, claim_gh_expr);

        let claim_hf_expr = prover_context.add_value(claim_hf);
        let (_, data_hf) =
            zk_reduce_sumcheck_to_evaluation(product_hf, &mut prover_context, claim_hf_expr);

        eprintln!("  Sumcheck time: {:?}", sumcheck_start.elapsed());

        // Build constraints
        build_all_constraints(
            ([commitment_f, commitment_g, commitment_h], [data_fg, data_gh, data_hf]),
            &mut prover_context,
        );

        // Prove
        eprintln!("Finalizing ZK proof...");
        let finalize_start = std::time::Instant::now();
        let zkproof = prover_context.prove(&mut rng, Some(&zk_basefold_prover));
        eprintln!("  Finalization time: {:?}", finalize_start.elapsed());
        eprintln!("Total prover time: {:?}", prover_start.elapsed());
        zkproof
    };

    //
    // Verifier Side
    //
    eprintln!("\n=== VERIFIER SIDE ===");
    {
        let verifier_start = std::time::Instant::now();

        let mut context: StackedPcsZkVerificationContext<GC> = zkproof.open();

        let (commitments, sumchecks) = read_all::<GC, _>(&mut context);
        build_all_constraints((commitments, sumchecks), &mut context);

        eprintln!("Finalizing ZK proof verification...");
        let verify_final_start = std::time::Instant::now();
        context.verify(Some(&zk_stacked_verifier)).expect("Failed to verify");
        eprintln!("  Final verification time: {:?}", verify_final_start.elapsed());
        eprintln!("Total verifier time: {:?}", verifier_start.elapsed());
    }

    eprintln!("\n=== TEST PASSED ===");
}
