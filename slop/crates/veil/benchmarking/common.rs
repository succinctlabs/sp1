// Shared benchmark helpers. Included by benchmarking binaries via include!().
// Do not add #![...] attributes or fn main() here.

use std::time::{Duration, Instant};

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

// ============================================================================
// Data generation
// ============================================================================

fn generate_random_mle(rng: &mut impl rand::Rng, num_vars: u32) -> (Mle<F>, Mle<EF>, EF) {
    let original_mle = Mle::<F>::rand(rng, 1, num_vars);
    let ef_data: Vec<EF> = original_mle.guts().as_slice().iter().map(|&x| EF::from(x)).collect();
    let mle_ef = Mle::new(RowMajorMatrix::new(ef_data, 1).into());
    let claim: EF = original_mle.guts().as_slice().iter().copied().sum::<F>().into();
    (original_mle, mle_ef, claim)
}

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

// ============================================================================
// Single MLE: read / build_constraints / run_standard / run_zk
// ============================================================================

fn single_mle_read<C: ReadingCtx>(
    ctx: &mut C,
    num_encoding_variables: u32,
    log_num_polynomials: u32,
    num_variables: u32,
) -> (C::MleOracle, slop_veil::protocols::sumcheck::SumcheckView<C>) {
    let oracle = ctx.read_oracle(num_encoding_variables, log_num_polynomials).unwrap();
    let param = SumcheckParam::new(num_variables, 1);
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

fn run_standard_single(
    original_mle: &Mle<F>,
    mle_ef: &Mle<EF>,
    claim: EF,
    num_encoding_variables: u32,
    log_num_polynomials: u32,
    num_variables: u32,
) -> (Duration, Duration) {
    let basefold_verifier = BasefoldVerifier::<GC>::new(FriConfig::default_fri_config(), 1);

    let (commitment, sumcheck_proof, pcs_proof, prover_time) = {
        let prover_start = Instant::now();

        let basefold_prover = BasefoldProver::<GC, MK>::new(&basefold_verifier);
        let batch_size = 1usize << log_num_polynomials;
        let stacked_prover = StackedPcsProver::new(basefold_prover, num_encoding_variables, batch_size);

        let mle_message = slop_commit::Message::from(vec![original_mle.clone()]);
        let (commitment, prover_data, _) = stacked_prover.commit_multilinears(mle_message).unwrap();

        let mut prover_challenger = GC::default_challenger();
        prover_challenger.observe(commitment);

        let (sumcheck_proof, _) = reduce_sumcheck_to_evaluation::<F, EF, _>(
            vec![mle_ef.clone()],
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

        (commitment, sumcheck_proof, pcs_proof, prover_start.elapsed())
    };

    let verifier_time = {
        let verifier_start = Instant::now();

        let stacked_verifier = StackedPcsVerifier::new(basefold_verifier, num_encoding_variables);
        let mut verifier_challenger = GC::default_challenger();
        verifier_challenger.observe(commitment);

        partially_verify_sumcheck_proof::<F, EF, _>(
            &sumcheck_proof,
            &mut verifier_challenger,
            num_variables as usize,
            1,
        )
        .unwrap();

        let (eval_point, eval_claim) = sumcheck_proof.point_and_eval.clone();
        let round_area = (1usize << num_variables).next_multiple_of(1usize << num_encoding_variables);
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

        verifier_start.elapsed()
    };

    (prover_time, verifier_time)
}

fn run_zk_single(
    original_mle: &Mle<F>,
    mle_ef: &Mle<EF>,
    claim: EF,
    num_encoding_variables: u32,
    log_num_polynomials: u32,
    num_variables: u32,
    rng: &mut ChaCha20Rng,
) -> (Duration, Duration) {
    let (pcs_prover, zk_stacked_verifier) =
        initialize_zk_prover_and_verifier::<GC, MK>(1, num_encoding_variables);

    let param = SumcheckParam::new(num_variables, 1);

    let (zkproof, prover_time) = {
        let prover_start = Instant::now();

        let masks_length = compute_mask_length::<GC, _>(
            |ctx| single_mle_read(ctx, num_encoding_variables, log_num_polynomials, num_variables),
            |(oracle, view), ctx| single_mle_build_constraints(ctx, oracle, view),
        );

        let mut ctx: StackedPcsZkProverCtx<GC, MK> =
            ZkProverCtx::initialize_with_pcs_only_lin(masks_length, pcs_prover, rng);

        let commit = ctx.commit_mle(original_mle.clone(), log_num_polynomials, rng).unwrap();

        let view = param.prove(mle_ef.clone(), &mut ctx, claim);
        let point: Point<EF> = Point::from(view.point.clone());
        ctx.assert_mle_eval(commit, point, view.claimed_eval.clone());
        view.build_constraints(&mut ctx).unwrap();

        let zkproof = ctx.prove(rng);
        (zkproof, prover_start.elapsed())
    };

    let verifier_time = {
        let verifier_start = Instant::now();

        let mut ctx = ZkVerifierCtx::init(zkproof, Some(zk_stacked_verifier));
        let (oracle, view) =
            single_mle_read(&mut ctx, num_encoding_variables, log_num_polynomials, num_variables);
        single_mle_build_constraints(&mut ctx, oracle, view);
        ctx.verify().expect("Failed to verify");

        verifier_start.elapsed()
    };

    (prover_time, verifier_time)
}

// ============================================================================
// Hadamard: read / build_constraints / run_standard / run_zk
// ============================================================================

struct HadamardReadData<C: ConstraintCtx> {
    ci_base: C::MleOracle,
    ci_ext: C::MleOracle,
    view: slop_veil::protocols::sumcheck::SumcheckView<C>,
}

fn hadamard_read<C: ReadingCtx>(
    ctx: &mut C,
    num_encoding_variables: u32,
    log_num_polynomials: u32,
    num_variables: u32,
) -> HadamardReadData<C> {
    let ci_base = ctx.read_oracle(num_encoding_variables, log_num_polynomials).unwrap();
    let ci_ext = ctx.read_oracle(num_encoding_variables, log_num_polynomials).unwrap();
    let param = SumcheckParam::with_component_evals(num_variables, 2, 2);
    let view = param.read(ctx).unwrap();
    HadamardReadData { ci_base, ci_ext, view }
}

fn hadamard_build_constraints<C: ConstraintCtx>(ctx: &mut C, data: HadamardReadData<C>) {
    let point: Point<C::Challenge> = Point::from(data.view.point.clone());
    let base_eval = data.view.component_evals[0].clone();
    let ext_eval = data.view.component_evals[1].clone();
    ctx.assert_a_times_b_equals_c(
        base_eval.clone(),
        ext_eval.clone(),
        data.view.claimed_eval.clone(),
    );
    ctx.assert_mle_multi_eval(vec![(data.ci_base, base_eval), (data.ci_ext, ext_eval)], point);
    data.view.build_constraints(ctx).unwrap();
}

fn run_standard_hadamard(
    mle_1: &Mle<F>,
    mle_2: &Mle<F>,
    hadamard_product: HadamardProduct<F, EF>,
    claim: EF,
    num_encoding_variables: u32,
    log_num_polynomials: u32,
    num_variables: u32,
) -> (Duration, Duration, u64) {
    let basefold_verifier = BasefoldVerifier::<GC>::new(FriConfig::default_fri_config(), 2);

    let (commitments, sumcheck_proof, pcs_proof, prover_time) = {
        let prover_start = Instant::now();

        let basefold_prover = BasefoldProver::<GC, MK>::new(&basefold_verifier);
        let batch_size = 1usize << log_num_polynomials;
        let stacked_prover = StackedPcsProver::new(basefold_prover, num_encoding_variables, batch_size);

        let (commitment_1, prover_data_1, _) = stacked_prover
            .commit_multilinears(slop_commit::Message::from(vec![mle_1.clone()]))
            .unwrap();
        let (commitment_2, prover_data_2, _) = stacked_prover
            .commit_multilinears(slop_commit::Message::from(vec![mle_2.clone()]))
            .unwrap();

        let mut challenger = GC::default_challenger();
        challenger.observe(commitment_1);
        challenger.observe(commitment_2);

        let lambda: EF = slop_challenger::CanSample::sample(&mut challenger);
        let (sumcheck_proof, _) = reduce_sumcheck_to_evaluation::<F, EF, _>(
            vec![hadamard_product],
            &mut challenger,
            vec![claim],
            1,
            lambda,
        );

        let (eval_point, _) = sumcheck_proof.point_and_eval.clone();
        let (batch_point, stack_point) =
            eval_point.split_at(eval_point.dimension() - num_encoding_variables as usize);
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
                &mut challenger,
            )
            .unwrap();

        ([commitment_1, commitment_2], sumcheck_proof, pcs_proof, prover_start.elapsed())
    };

    let commitment_bytes: u64 = commitments.iter().map(|c| serialized_size(c).unwrap()).sum();
    let sumcheck_bytes = serialized_size(&sumcheck_proof).unwrap();
    let pcs_bytes = serialized_size(&pcs_proof).unwrap();
    let proof_bytes = commitment_bytes + sumcheck_bytes + pcs_bytes;

    let verifier_time = {
        let verifier_start = Instant::now();

        let stacked_verifier = StackedPcsVerifier::new(basefold_verifier, num_encoding_variables);
        let mut challenger = GC::default_challenger();
        challenger.observe(commitments[0]);
        challenger.observe(commitments[1]);

        let _lambda: EF = slop_challenger::CanSample::sample(&mut challenger);

        partially_verify_sumcheck_proof::<F, EF, _>(
            &sumcheck_proof,
            &mut challenger,
            num_variables as usize,
            2,
        )
        .unwrap();

        let (eval_point, _) = sumcheck_proof.point_and_eval.clone();
        let round_area =
            (1usize << num_variables).next_multiple_of(1usize << num_encoding_variables);
        let (batch_point, _) =
            eval_point.split_at(eval_point.dimension() - num_encoding_variables as usize);
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
                &mut challenger,
            )
            .unwrap();

        verifier_start.elapsed()
    };

    (prover_time, verifier_time, proof_bytes)
}

#[allow(clippy::too_many_arguments)]
fn run_zk_hadamard(
    mle_1: &Mle<F>,
    mle_2: &Mle<F>,
    hadamard_product: HadamardProduct<F, EF>,
    claim: EF,
    num_encoding_variables: u32,
    log_num_polynomials: u32,
    num_variables: u32,
    rng: &mut ChaCha20Rng,
) -> (Duration, Duration, u64) {
    let (pcs_prover, zk_stacked_verifier) =
        initialize_zk_prover_and_verifier::<GC, MK>(2, num_encoding_variables);

    let param = SumcheckParam::with_component_evals(num_variables, 2, 2);

    let (zkproof, prover_time) = {
        let prover_start = Instant::now();

        let masks_length = compute_mask_length::<GC, _>(
            |ctx| hadamard_read(ctx, num_encoding_variables, log_num_polynomials, num_variables),
            |data, ctx| hadamard_build_constraints(ctx, data),
        );

        let mut ctx: StackedPcsZkProverCtx<GC, MK> =
            ZkProverCtx::initialize_with_pcs(masks_length, pcs_prover, rng);

        let ci_base = ctx.commit_mle(mle_1.clone(), log_num_polynomials, rng).unwrap();
        let ci_ext = ctx.commit_mle(mle_2.clone(), log_num_polynomials, rng).unwrap();

        let view = param.prove(hadamard_product, &mut ctx, claim);
        let data = HadamardReadData { ci_base, ci_ext, view };
        hadamard_build_constraints(&mut ctx, data);

        let zkproof = ctx.prove(rng);
        (zkproof, prover_start.elapsed())
    };

    let proof_bytes = serialized_size(&zkproof).unwrap();

    let verifier_time = {
        let verifier_start = Instant::now();

        let mut ctx = ZkVerifierCtx::init(zkproof, Some(zk_stacked_verifier));
        let data =
            hadamard_read(&mut ctx, num_encoding_variables, log_num_polynomials, num_variables);
        hadamard_build_constraints(&mut ctx, data);
        ctx.verify().expect("Failed to verify");

        verifier_start.elapsed()
    };

    (prover_time, verifier_time, proof_bytes)
}

// ============================================================================
// Utilities
// ============================================================================

fn median(samples: &mut [Duration]) -> Duration {
    samples.sort();
    let n = samples.len();
    if n % 2 == 1 {
        samples[n / 2]
    } else {
        (samples[n / 2 - 1] + samples[n / 2]) / 2
    }
}

fn stddev_ms(samples: &[Duration]) -> f64 {
    let n = samples.len() as f64;
    let mean = samples.iter().map(|d| d.as_secs_f64()).sum::<f64>() / n;
    let variance =
        samples.iter().map(|d| (d.as_secs_f64() - mean).powi(2)).sum::<f64>() / (n - 1.0);
    variance.sqrt() * 1000.0
}
