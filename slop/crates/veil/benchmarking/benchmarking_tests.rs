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
use slop_jagged::{HadamardProduct, LongMle};
use slop_koala_bear::KoalaBearDegree4Duplex;
use slop_matrix::dense::RowMajorMatrix;
use slop_merkle_tree::Poseidon2KoalaBear16Prover;
use slop_multilinear::{Mle, MultilinearPcsProver, Point};
use slop_stacked::{StackedPcsProver, StackedPcsVerifier};
use slop_sumcheck::{partially_verify_sumcheck_proof, reduce_sumcheck_to_evaluation};
use slop_veil::compiler::{ConstraintCtx, ReadingCtx};
use slop_veil::protocols::sumcheck::SumcheckParam;
use slop_veil::zk::stacked_pcs::{initialize_zk_prover_and_verifier, StackedPcsZkProverCtx};
use slop_veil::zk::{compute_mask_length, ZkProverCtx, ZkVerifierCtx};

type GC = KoalaBearDegree4Duplex;
type F = <GC as IopCtx>::F;
type EF = <GC as IopCtx>::EF;
type MK = Poseidon2KoalaBear16Prover;

/// Generates a random MLE and converts it for sumcheck.
///
/// Returns `(original_mle, mle_ef, claim)` where:
/// - `original_mle`: the random MLE in the base field
/// - `mle_ef`: extension field version for sumcheck
/// - `claim`: sum of all evaluations (the sumcheck claim)
fn generate_random_mle(rng: &mut impl rand::Rng, num_vars: u32) -> (Mle<F>, Mle<EF>, EF) {
    let original_mle = Mle::<F>::rand(rng, 1, num_vars);

    let ef_data: Vec<EF> = original_mle.guts().as_slice().iter().map(|&x| EF::from(x)).collect();
    let mle_ef = Mle::new(RowMajorMatrix::new(ef_data, 1).into());

    let claim: EF = original_mle.guts().as_slice().iter().copied().sum::<F>().into();

    (original_mle, mle_ef, claim)
}

// ============================================================================
// Benchmark 1: Single MLE sumcheck + PCS
// ============================================================================

const SINGLE_NUM_STACKED_VARS: u32 = 16;
const SINGLE_LOG_STACKING_HEIGHT: u32 = 8;
const SINGLE_TOTAL_NUM_VARS: u32 = SINGLE_LOG_STACKING_HEIGHT + SINGLE_NUM_STACKED_VARS;

fn single_mle_read_and_verify<C: ReadingCtx>(
    ctx: &mut C,
) -> (C::MleOracle, slop_veil::protocols::sumcheck::SumcheckView<C>) {
    let oracle = ctx.read_oracle(SINGLE_NUM_STACKED_VARS, SINGLE_LOG_STACKING_HEIGHT).unwrap();
    let param = SumcheckParam::new(SINGLE_TOTAL_NUM_VARS, 1);
    let view = param.read(ctx).unwrap();
    (oracle, view)
}

fn single_mle_build_constraints<C: ConstraintCtx>(
    ctx: &mut C,
    oracle: C::MleOracle,
    view: slop_veil::protocols::sumcheck::SumcheckView<C>,
) {
    let point: Point<C::Challenge> = Point::from(view.point.clone());
    ctx.assert_mle_eval(oracle, point, view.claimed_eval.clone());
    view.build_constraints(ctx).unwrap();
}

/// Benchmarks ZK sumcheck + PCS eval vs standard sumcheck + PCS eval for a single MLE.
#[test]
fn benchmark_zk_vs_standard_sumcheck_with_pcs() {
    eprintln!("\n========================================");
    eprintln!("Benchmark: ZK vs Standard Sumcheck + PCS");
    eprintln!("  Total variables: {SINGLE_TOTAL_NUM_VARS}");
    eprintln!("  MLE size: 2^{SINGLE_TOTAL_NUM_VARS} = {}", 1u64 << SINGLE_TOTAL_NUM_VARS);
    eprintln!(
        "  Stacking: log_height={SINGLE_LOG_STACKING_HEIGHT}, stacked_vars={SINGLE_NUM_STACKED_VARS}"
    );
    eprintln!("========================================\n");

    let mut rng = ChaCha20Rng::from_entropy();
    let (original_mle, mle_ef, claim) = generate_random_mle(&mut rng, SINGLE_TOTAL_NUM_VARS);
    let mle_ef_copy = mle_ef.clone();

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

    // ================================================================
    // STANDARD PATH
    // ================================================================
    eprintln!("===== STANDARD SUMCHECK + STACKED PCS =====");

    let basefold_verifier = BasefoldVerifier::<GC>::new(FriConfig::default_fri_config(), 1);

    let (commitment, sumcheck_proof, pcs_proof, standard_prover_time) = {
        let prover_start = Instant::now();

        let basefold_prover = BasefoldProver::<GC, MK>::new(&basefold_verifier);
        let batch_size = 1usize << SINGLE_LOG_STACKING_HEIGHT;
        let stacked_prover =
            StackedPcsProver::new(basefold_prover, SINGLE_NUM_STACKED_VARS, batch_size);

        let mle_message = slop_commit::Message::from(vec![original_mle.clone()]);
        let (commitment, prover_data, _) = stacked_prover.commit_multilinears(mle_message).unwrap();

        let mut prover_challenger = GC::default_challenger();
        prover_challenger.observe(commitment);

        let (sumcheck_proof, _) = reduce_sumcheck_to_evaluation::<F, EF, _>(
            vec![mle_ef],
            &mut prover_challenger,
            vec![claim],
            1,
            EF::one(),
        );

        let (eval_point, eval_claim) = sumcheck_proof.point_and_eval.clone();
        let pcs_proof = stacked_prover
            .prove_trusted_evaluation(
                eval_point,
                eval_claim,
                Rounds { rounds: vec![prover_data] },
                &mut prover_challenger,
            )
            .unwrap();

        let prover_total = prover_start.elapsed();
        eprintln!("  PROVER TOTAL:      {:?}", prover_total);
        (commitment, sumcheck_proof, pcs_proof, prover_total)
    };

    let fe = std::mem::size_of::<F>() as u64;
    let commitment_bytes = serialized_size(&commitment).unwrap();
    let sumcheck_bytes = serialized_size(&sumcheck_proof).unwrap();
    let pcs_bytes = serialized_size(&pcs_proof).unwrap();
    let standard_proof_bytes = commitment_bytes + sumcheck_bytes + pcs_bytes;
    let standard_proof_felts = standard_proof_bytes / fe;
    eprintln!("  Proof size:        {standard_proof_bytes} bytes ({standard_proof_felts} felts)");

    let standard_verifier_time = {
        let verifier_start = Instant::now();

        let stacked_verifier = StackedPcsVerifier::new(basefold_verifier, SINGLE_NUM_STACKED_VARS);

        let mut verifier_challenger = GC::default_challenger();
        verifier_challenger.observe(commitment);

        partially_verify_sumcheck_proof::<F, EF, _>(
            &sumcheck_proof,
            &mut verifier_challenger,
            SINGLE_TOTAL_NUM_VARS as usize,
            1,
        )
        .unwrap();

        let (eval_point, eval_claim) = sumcheck_proof.point_and_eval.clone();
        let round_area =
            (1usize << SINGLE_TOTAL_NUM_VARS).next_multiple_of(1usize << SINGLE_NUM_STACKED_VARS);
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

        let verifier_total = verifier_start.elapsed();
        eprintln!("  VERIFIER TOTAL:    {:?}", verifier_total);
        verifier_total
    };

    // ================================================================
    // ZK PATH
    // ================================================================
    eprintln!("\n===== ZK SUMCHECK + ZK STACKED PCS =====");

    let (pcs_prover, zk_stacked_verifier) =
        initialize_zk_prover_and_verifier::<GC, MK>(1, SINGLE_NUM_STACKED_VARS);

    let param = SumcheckParam::new(SINGLE_TOTAL_NUM_VARS, 1);

    let (zkproof, zk_prover_time) = {
        let prover_start = Instant::now();

        let masks_length =
            compute_mask_length::<GC, _>(single_mle_read_and_verify, |(oracle, view), ctx| {
                single_mle_build_constraints(ctx, oracle, view)
            });
        eprintln!("  masks_length: {masks_length}");

        let mut ctx: StackedPcsZkProverCtx<GC, MK> =
            ZkProverCtx::initialize_with_pcs_only_lin(masks_length, pcs_prover, &mut rng);

        let commit =
            ctx.commit_mle(original_mle.clone(), SINGLE_LOG_STACKING_HEIGHT, &mut rng).unwrap();

        let view = param.prove(mle_ef_copy, &mut ctx, claim);
        let point: Point<EF> = Point::from(view.point.clone());
        ctx.assert_mle_eval(commit, point, view.claimed_eval.clone());
        view.build_constraints(&mut ctx).unwrap();

        let zkproof = ctx.prove(&mut rng);

        let prover_total = prover_start.elapsed();
        eprintln!("  PROVER TOTAL:      {:?}", prover_total);
        (zkproof, prover_total)
    };

    let zk_proof_bytes = serialized_size(&zkproof).unwrap();
    let zk_proof_felts = zk_proof_bytes / fe;
    eprintln!("  Proof size:        {zk_proof_bytes} bytes ({zk_proof_felts} felts)");

    let zk_verifier_time = {
        let verifier_start = Instant::now();

        let mut ctx = ZkVerifierCtx::init(zkproof, Some(zk_stacked_verifier));
        let (oracle, view) = single_mle_read_and_verify(&mut ctx);
        single_mle_build_constraints(&mut ctx, oracle, view);
        ctx.verify().expect("Failed to verify");

        let verifier_total = verifier_start.elapsed();
        eprintln!("  VERIFIER TOTAL:    {:?}", verifier_total);
        verifier_total
    };

    // ================================================================
    // Summary
    // ================================================================
    eprintln!("\n===== SUMMARY =====");
    eprintln!(
        "  Standard prover:  {:?}  |  ZK prover:  {:?}  |  ZK overhead: {:.2}x",
        standard_prover_time,
        zk_prover_time,
        zk_prover_time.as_secs_f64() / standard_prover_time.as_secs_f64()
    );
    eprintln!(
        "  Standard verifier: {:?}  |  ZK verifier: {:?}  |  ZK overhead: {:.2}x",
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

// ============================================================================
// Benchmark 2: Hadamard product with batched assert_mle_multi_eval
// ============================================================================

/// Generates two random MLEs and prepares a Hadamard product for sumcheck.
#[allow(clippy::type_complexity)]
fn generate_random_hadamard_product(
    rng: &mut impl rand::Rng,
    num_vars: u32,
) -> (Mle<F>, Mle<F>, HadamardProduct<F, EF>, EF) {
    let mle_1 = Mle::<F>::rand(rng, 1, num_vars);
    let mle_2 = Mle::<F>::rand(rng, 1, num_vars);

    let long_base = LongMle::from_components(vec![mle_1.clone()], num_vars);
    let mle_2_ef_data: Vec<EF> = mle_2.guts().as_slice().iter().map(|&x| EF::from(x)).collect();
    let mle_2_as_ef = Mle::new(RowMajorMatrix::new(mle_2_ef_data, 1).into());
    let long_ext = LongMle::from_components(vec![mle_2_as_ef], num_vars);
    let product = HadamardProduct { base: long_base, ext: long_ext };

    let claim: EF = mle_1
        .guts()
        .as_slice()
        .iter()
        .zip(mle_2.guts().as_slice().iter())
        .map(|(&b, &e)| EF::from(b) * EF::from(e))
        .sum();

    (mle_1, mle_2, product, claim)
}

/// Data read from the Hadamard proof transcript.
struct HadamardReadData<C: ConstraintCtx> {
    ci_base: C::MleOracle,
    ci_ext: C::MleOracle,
    view: slop_veil::protocols::sumcheck::SumcheckView<C>,
}

fn hadamard_read<C: ReadingCtx>(
    ctx: &mut C,
    num_stacked_vars: u32,
    log_stacking_height: u32,
    total_num_vars: u32,
) -> HadamardReadData<C> {
    let ci_base = ctx.read_oracle(num_stacked_vars, log_stacking_height).unwrap();
    let ci_ext = ctx.read_oracle(num_stacked_vars, log_stacking_height).unwrap();
    // 2 component evals: base_eval and ext_eval from the Hadamard product
    let param = SumcheckParam::with_component_evals(total_num_vars, 2, 2);
    let view = param.read(ctx).unwrap();
    HadamardReadData { ci_base, ci_ext, view }
}

fn hadamard_build_constraints<C: ConstraintCtx>(ctx: &mut C, data: HadamardReadData<C>) {
    let point: Point<C::Challenge> = Point::from(data.view.point.clone());
    let base_eval = data.view.component_evals[0].clone();
    let ext_eval = data.view.component_evals[1].clone();
    // Constrain: base_eval * ext_eval == claimed_eval (the Hadamard product at the point)
    ctx.assert_a_times_b_equals_c(
        base_eval.clone(),
        ext_eval.clone(),
        data.view.claimed_eval.clone(),
    );
    // Batch both PCS openings at the same point via assert_mle_multi_eval
    ctx.assert_mle_multi_eval(vec![(data.ci_base, base_eval), (data.ci_ext, ext_eval)], point);
    data.view.build_constraints(ctx).unwrap();
}

fn run_hadamard_benchmark(num_stacked_vars: u32, log_stacking_height: u32) {
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
    let hadamard_product_copy = hadamard_product.clone();

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

    // ================================================================
    // STANDARD PATH
    // ================================================================
    eprintln!("===== STANDARD HADAMARD SUMCHECK + STACKED PCS =====");

    let basefold_verifier = BasefoldVerifier::<GC>::new(FriConfig::default_fri_config(), 2);

    let (commitments, sumcheck_proof, pcs_proof, standard_prover_time) = {
        let prover_start = Instant::now();

        let basefold_prover = BasefoldProver::<GC, MK>::new(&basefold_verifier);
        let batch_size = 1usize << log_stacking_height;
        let stacked_prover = StackedPcsProver::new(basefold_prover, num_stacked_vars, batch_size);

        let mle_1_msg = slop_commit::Message::from(vec![mle_1.clone()]);
        let (commitment_1, prover_data_1, _) =
            stacked_prover.commit_multilinears(mle_1_msg).unwrap();
        let mle_2_msg = slop_commit::Message::from(vec![mle_2.clone()]);
        let (commitment_2, prover_data_2, _) =
            stacked_prover.commit_multilinears(mle_2_msg).unwrap();

        let mut prover_challenger = GC::default_challenger();
        prover_challenger.observe(commitment_1);
        prover_challenger.observe(commitment_2);

        let lambda: EF = slop_challenger::CanSample::sample(&mut prover_challenger);
        let (sumcheck_proof, _) = reduce_sumcheck_to_evaluation::<F, EF, _>(
            vec![hadamard_product],
            &mut prover_challenger,
            vec![claim],
            1,
            lambda,
        );

        let (eval_point, _) = sumcheck_proof.point_and_eval.clone();

        let (batch_point, stack_point) =
            eval_point.split_at(eval_point.dimension() - num_stacked_vars as usize);
        let batch_evals_1 = stacked_prover.round_batch_evaluations(&stack_point, &prover_data_1);
        let batch_evals_2 = stacked_prover.round_batch_evaluations(&stack_point, &prover_data_2);
        let batch_evals_mle: Mle<EF> =
            [batch_evals_1, batch_evals_2].into_iter().flatten().flatten().collect();
        let eval_claim = batch_evals_mle.blocking_eval_at(&batch_point)[0];

        let pcs_proof = stacked_prover
            .prove_trusted_evaluation(
                eval_point,
                eval_claim,
                Rounds { rounds: vec![prover_data_1, prover_data_2] },
                &mut prover_challenger,
            )
            .unwrap();

        let prover_total = prover_start.elapsed();
        eprintln!("  PROVER TOTAL:      {:?}", prover_total);
        ([commitment_1, commitment_2], sumcheck_proof, pcs_proof, prover_total)
    };

    let fe = std::mem::size_of::<F>() as u64;
    let commitment_bytes: u64 = commitments.iter().map(|c| serialized_size(c).unwrap()).sum();
    let sumcheck_bytes = serialized_size(&sumcheck_proof).unwrap();
    let pcs_bytes = serialized_size(&pcs_proof).unwrap();
    let standard_proof_bytes = commitment_bytes + sumcheck_bytes + pcs_bytes;
    let standard_proof_felts = standard_proof_bytes / fe;
    eprintln!("  Proof size:        {standard_proof_bytes} bytes ({standard_proof_felts} felts)");

    let standard_verifier_time = {
        let verifier_start = Instant::now();

        let stacked_verifier = StackedPcsVerifier::new(basefold_verifier, num_stacked_vars);

        let mut verifier_challenger = GC::default_challenger();
        verifier_challenger.observe(commitments[0]);
        verifier_challenger.observe(commitments[1]);

        let _lambda: EF = slop_challenger::CanSample::sample(&mut verifier_challenger);
        partially_verify_sumcheck_proof::<F, EF, _>(
            &sumcheck_proof,
            &mut verifier_challenger,
            total_num_vars as usize,
            2,
        )
        .unwrap();

        let (eval_point, _) = sumcheck_proof.point_and_eval.clone();
        let round_area = (1usize << total_num_vars).next_multiple_of(1usize << num_stacked_vars);

        let (batch_point, _) =
            eval_point.split_at(eval_point.dimension() - num_stacked_vars as usize);
        let batch_evals_mle: Mle<EF> =
            pcs_proof.batch_evaluations.iter().flatten().cloned().collect();
        let eval_claim = batch_evals_mle.blocking_eval_at(&batch_point)[0];

        stacked_verifier
            .verify_trusted_evaluation(
                &commitments,
                &[round_area, round_area],
                &eval_point,
                &pcs_proof,
                eval_claim,
                &mut verifier_challenger,
            )
            .unwrap();

        let verifier_total = verifier_start.elapsed();
        eprintln!("  VERIFIER TOTAL:    {:?}", verifier_total);
        verifier_total
    };

    // ================================================================
    // ZK PATH (with batched assert_mle_multi_eval)
    // ================================================================
    eprintln!("\n===== ZK HADAMARD SUMCHECK + ZK STACKED PCS (BATCHED) =====");

    let (pcs_prover, zk_stacked_verifier) =
        initialize_zk_prover_and_verifier::<GC, MK>(2, num_stacked_vars);

    // 2 component evals: base_eval and ext_eval from the Hadamard product
    let param = SumcheckParam::with_component_evals(total_num_vars, 2, 2);

    let (zkproof, zk_prover_time) = {
        let prover_start = Instant::now();

        let masks_length = compute_mask_length::<GC, _>(
            |ctx| hadamard_read(ctx, num_stacked_vars, log_stacking_height, total_num_vars),
            |data, ctx| hadamard_build_constraints(ctx, data),
        );
        eprintln!("  masks_length: {masks_length}");

        let mut ctx: StackedPcsZkProverCtx<GC, MK> =
            ZkProverCtx::initialize_with_pcs(masks_length, pcs_prover, &mut rng);

        let ci_base = ctx.commit_mle(mle_1.clone(), log_stacking_height, &mut rng).unwrap();
        let ci_ext = ctx.commit_mle(mle_2.clone(), log_stacking_height, &mut rng).unwrap();

        let view = param.prove(hadamard_product_copy, &mut ctx, claim);
        let data = HadamardReadData { ci_base, ci_ext, view };
        hadamard_build_constraints(&mut ctx, data);

        let zkproof = ctx.prove(&mut rng);

        let prover_total = prover_start.elapsed();
        eprintln!("  PROVER TOTAL:      {:?}", prover_total);
        (zkproof, prover_total)
    };

    let zk_proof_bytes = serialized_size(&zkproof).unwrap();
    let zk_proof_felts = zk_proof_bytes / fe;
    eprintln!("  Proof size:        {zk_proof_bytes} bytes ({zk_proof_felts} felts)");

    let zk_verifier_time = {
        let verifier_start = Instant::now();

        let mut ctx = ZkVerifierCtx::init(zkproof, Some(zk_stacked_verifier));
        let data = hadamard_read(&mut ctx, num_stacked_vars, log_stacking_height, total_num_vars);
        hadamard_build_constraints(&mut ctx, data);
        ctx.verify().expect("Failed to verify");

        let verifier_total = verifier_start.elapsed();
        eprintln!("  VERIFIER TOTAL:    {:?}", verifier_total);
        verifier_total
    };

    // ================================================================
    // Summary
    // ================================================================
    eprintln!("\n===== SUMMARY =====");
    eprintln!(
        "  Standard prover:  {:?}  |  ZK prover:  {:?}  |  ZK overhead: {:.2}x",
        standard_prover_time,
        zk_prover_time,
        zk_prover_time.as_secs_f64() / standard_prover_time.as_secs_f64()
    );
    eprintln!(
        "  Standard verifier: {:?}  |  ZK verifier: {:?}  |  ZK overhead: {:.2}x",
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

/// Hadamard benchmark with batched PCS eval via assert_mle_multi_eval.
#[test]
fn benchmark_zk_vs_standard_hadamard_sumcheck_with_pcs() {
    run_hadamard_benchmark(19, 8);
}
