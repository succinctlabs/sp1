//! End-to-end test scenarios, written generically over `SendingCtx` /
//! `ReadingCtx`. Each backend's `tests.rs` wraps these with concrete context
//! init + finalize.
//!
//! Per scenario, three symmetric pieces:
//!
//! - `*_prove`   — prover side: emit transcript, return the view.
//! - `*_read`    — verifier side: read transcript, return the view.
//! - `*_build_constraints` — shared: emit constraints from the view.
//!
//! The concrete per-backend test files call them as `prove / read →
//! build_constraints → ctx.prove() / verify()` on each side. The ZK backend's
//! [`compute_mask_length`](slop_veil::zk::compute_mask_length) also consumes
//! the `*_read` / `*_build_constraints` pair on the verifier side.

use slop_algebra::{AbstractExtensionField, AbstractField, Field};
use slop_jagged::{HadamardProduct, LongMle};
use slop_matrix::dense::RowMajorMatrix;
use slop_multilinear::{Mle, Point};
use slop_sumcheck::SumcheckPolyFirstRound;

use slop_veil::compiler::{ConstraintCtx, ReadingCtx, SendingCtx};
use slop_veil::protocols::sumcheck::{SumcheckInputClaim, SumcheckParam, SumcheckView};

// ============================================================================
// Scenario #1: Hadamard-product sumcheck, no PCS.
//
// Sumcheck a degree-2 product of two multilinears over `num_vars` variables,
// emit only round-consistency constraints. No oracles, no PCS.
// ============================================================================

pub fn sumcheck_no_pcs_read<C: ReadingCtx>(ctx: &mut C, num_variables: u32) -> SumcheckView<C> {
    // degree 2 (product of two multilinears), 2 component evals (one per factor).
    SumcheckParam::with_component_evals(num_variables, 2, 2)
        .read(ctx)
        .expect("sumcheck read failed")
}

pub fn sumcheck_no_pcs_build_constraints<C: ConstraintCtx>(
    view: SumcheckView<C>,
    ctx: &mut C,
    claim: C::Extension,
) {
    let in_claim = SumcheckInputClaim::from_value(claim);
    view.build_constraints(&in_claim, ctx).expect("sumcheck build_constraints failed");
}

/// Prover-side mirror of [`sumcheck_no_pcs_read`]: run the sumcheck against
/// `poly` with hypercube sum `claim`, emit the transcript, and return the view.
pub fn sumcheck_no_pcs_prove<C, P>(
    ctx: &mut C,
    num_variables: u32,
    poly: P,
    claim: C::Extension,
) -> SumcheckView<C>
where
    C: SendingCtx,
    P: SumcheckPolyFirstRound<C::Extension>,
{
    let param = SumcheckParam::with_component_evals(num_variables, 2, 2);
    let in_claim = SumcheckInputClaim::from_value(claim);
    param.prove(&in_claim, poly, ctx)
}

// ============================================================================
// Scenario #2: single-MLE sumcheck + 1 PCS eval.
//
// Commit one MLE, run a basic (degree-1) sumcheck on it, discharge the final
// eval claim via `assert_mle_eval`. The sumcheck's `claimed_eval` is the MLE's
// value at the random point, so no separate component eval is needed.
// ============================================================================

pub struct SumcheckSingleMleView<C: ConstraintCtx> {
    pub oracle: C::MleOracle,
    pub sumcheck_view: SumcheckView<C>,
}

pub fn sumcheck_single_mle_read<C: ReadingCtx>(
    ctx: &mut C,
    num_encoding_variables: u32,
    log_num_polynomials: u32,
) -> SumcheckSingleMleView<C> {
    let oracle =
        ctx.read_oracle(num_encoding_variables, log_num_polynomials).expect("read_oracle failed");
    let num_vars = num_encoding_variables + log_num_polynomials;
    let sumcheck_view = SumcheckParam::new(num_vars, 1).read(ctx).expect("sumcheck read failed");
    SumcheckSingleMleView { oracle, sumcheck_view }
}

pub fn sumcheck_single_mle_build_constraints<C: ConstraintCtx>(
    view: SumcheckSingleMleView<C>,
    ctx: &mut C,
    claim: C::Extension,
) {
    let SumcheckSingleMleView { oracle, sumcheck_view } = view;
    let point = Point::from(sumcheck_view.out_claim.point.clone());
    let claimed_eval = sumcheck_view.out_claim.claimed_eval.clone();
    let in_claim = SumcheckInputClaim::from_value(claim);
    sumcheck_view.build_constraints(&in_claim, ctx).expect("sumcheck build_constraints failed");
    ctx.assert_mle_eval(oracle, point, claimed_eval);
}

pub fn sumcheck_single_mle_prove<C, RNG>(
    ctx: &mut C,
    num_encoding_variables: u32,
    log_num_polynomials: u32,
    original_mle: Mle<C::Field>,
    mle_ef: Mle<C::Extension>,
    claim: C::Extension,
    rng: &mut RNG,
) -> SumcheckSingleMleView<C>
where
    C: SendingCtx,
    RNG: rand::CryptoRng + rand::Rng,
    rand::distributions::Standard: rand::distributions::Distribution<C::Field>,
{
    let oracle = ctx.commit_mle(original_mle, log_num_polynomials, rng).expect("commit_mle failed");
    let num_vars = num_encoding_variables + log_num_polynomials;
    let in_claim = SumcheckInputClaim::from_value(claim);
    let sumcheck_view = SumcheckParam::new(num_vars, 1).prove(&in_claim, mle_ef, ctx);
    SumcheckSingleMleView { oracle, sumcheck_view }
}

// ============================================================================
// Scenario #3: Hadamard-product sumcheck + 2 PCS evals at the same point.
//
// Commit two MLEs (a base-field and an "ext" one), run a degree-2 Hadamard
// sumcheck on their elementwise product, then emit `a*b=c` tying the two
// component evals to the sumcheck's claimed eval, plus one
// `assert_mle_multi_eval` call that batches both oracles at the shared
// sumcheck point into a single PCS proof.
// ============================================================================

pub struct SumcheckHadamardView<C: ConstraintCtx> {
    pub oracle_base: C::MleOracle,
    pub oracle_ext: C::MleOracle,
    pub sumcheck_view: SumcheckView<C>,
}

pub fn sumcheck_hadamard_read<C: ReadingCtx>(
    ctx: &mut C,
    num_encoding_variables: u32,
    log_num_polynomials: u32,
) -> SumcheckHadamardView<C> {
    let oracle_base = ctx
        .read_oracle(num_encoding_variables, log_num_polynomials)
        .expect("read_oracle base failed");
    let oracle_ext = ctx
        .read_oracle(num_encoding_variables, log_num_polynomials)
        .expect("read_oracle ext failed");
    let num_vars = num_encoding_variables + log_num_polynomials;
    let sumcheck_view = SumcheckParam::with_component_evals(num_vars, 2, 2)
        .read(ctx)
        .expect("sumcheck read failed");
    SumcheckHadamardView { oracle_base, oracle_ext, sumcheck_view }
}

pub fn sumcheck_hadamard_build_constraints<C: ConstraintCtx>(
    view: SumcheckHadamardView<C>,
    ctx: &mut C,
    claim: C::Extension,
) {
    let SumcheckHadamardView { oracle_base, oracle_ext, sumcheck_view } = view;
    let point = Point::from(sumcheck_view.out_claim.point.clone());
    let base_eval = sumcheck_view.out_claim.component_evals[0][0].clone();
    let ext_eval = sumcheck_view.out_claim.component_evals[0][1].clone();
    let claimed_eval = sumcheck_view.out_claim.claimed_eval.clone();
    let in_claim = SumcheckInputClaim::from_value(claim);

    sumcheck_view.build_constraints(&in_claim, ctx).expect("sumcheck build_constraints failed");
    ctx.assert_a_times_b_equals_c(base_eval.clone(), ext_eval.clone(), claimed_eval).unwrap();
    // Batch both oracles at the shared sumcheck point into a single multi-eval
    // group → one PCS proof covering both commits.
    ctx.assert_mle_multi_eval(vec![(oracle_base, base_eval), (oracle_ext, ext_eval)], point);
}

#[allow(clippy::too_many_arguments)]
pub fn sumcheck_hadamard_prove<C, RNG>(
    ctx: &mut C,
    num_encoding_variables: u32,
    log_num_polynomials: u32,
    mle_base: Mle<C::Field>,
    mle_ext: Mle<C::Field>,
    product: HadamardProduct<C::Field, C::Extension>,
    claim: C::Extension,
    rng: &mut RNG,
) -> SumcheckHadamardView<C>
where
    C: SendingCtx,
    RNG: rand::CryptoRng + rand::Rng,
    rand::distributions::Standard: rand::distributions::Distribution<C::Field>,
{
    let oracle_base =
        ctx.commit_mle(mle_base, log_num_polynomials, rng).expect("commit base failed");
    let oracle_ext = ctx.commit_mle(mle_ext, log_num_polynomials, rng).expect("commit ext failed");
    let num_vars = num_encoding_variables + log_num_polynomials;
    let in_claim = SumcheckInputClaim::from_value(claim);
    let sumcheck_view =
        SumcheckParam::with_component_evals(num_vars, 2, 2).prove(&in_claim, product, ctx);
    SumcheckHadamardView { oracle_base, oracle_ext, sumcheck_view }
}

// ============================================================================
// Scenario #5: Triple Hadamard, multi-point.
//
// Commit three MLEs f, g, h and run three independent Hadamard sumchecks
// (fg at p1, gh at p2, hf at p3). Each sumcheck lands at its own random point,
// so each commit gets opened at two *different* points (f at p1 and p3; g at
// p1 and p2; h at p2 and p3) — exercising the multi-point PCS discharge path.
// Requires `C::MleOracle: Clone` since each commit is handed to two separate
// `assert_mle_eval` calls.
//
// The ZK backend's `assert_mle_multi_eval` machinery currently panics with
// "Multiple eval claims on the same PCS commitment" when the same commit is
// opened at multiple points, so the ZK facade marks this test `#[should_panic]`.
// The transparent backend's claim queue handles distinct-point groups directly
// and passes the test.
// ============================================================================

pub struct SumcheckTripleHadamardView<C: ConstraintCtx> {
    pub oracle_f: C::MleOracle,
    pub oracle_g: C::MleOracle,
    pub oracle_h: C::MleOracle,
    pub sumcheck_fg: SumcheckView<C>,
    pub sumcheck_gh: SumcheckView<C>,
    pub sumcheck_hf: SumcheckView<C>,
}

pub fn sumcheck_triple_hadamard_read<C: ReadingCtx>(
    ctx: &mut C,
    num_encoding_variables: u32,
    log_num_polynomials: u32,
) -> SumcheckTripleHadamardView<C> {
    let oracle_f =
        ctx.read_oracle(num_encoding_variables, log_num_polynomials).expect("read_oracle f failed");
    let oracle_g =
        ctx.read_oracle(num_encoding_variables, log_num_polynomials).expect("read_oracle g failed");
    let oracle_h =
        ctx.read_oracle(num_encoding_variables, log_num_polynomials).expect("read_oracle h failed");
    let num_vars = num_encoding_variables + log_num_polynomials;
    let param = SumcheckParam::with_component_evals(num_vars, 2, 2);
    let sumcheck_fg = param.read(ctx).expect("sumcheck fg read failed");
    let sumcheck_gh = param.read(ctx).expect("sumcheck gh read failed");
    let sumcheck_hf = param.read(ctx).expect("sumcheck hf read failed");
    SumcheckTripleHadamardView {
        oracle_f,
        oracle_g,
        oracle_h,
        sumcheck_fg,
        sumcheck_gh,
        sumcheck_hf,
    }
}

pub fn sumcheck_triple_hadamard_build_constraints<C>(
    view: SumcheckTripleHadamardView<C>,
    ctx: &mut C,
    claim_fg: C::Extension,
    claim_gh: C::Extension,
    claim_hf: C::Extension,
) where
    C: ConstraintCtx,
    C::MleOracle: Clone,
{
    let SumcheckTripleHadamardView {
        oracle_f,
        oracle_g,
        oracle_h,
        sumcheck_fg,
        sumcheck_gh,
        sumcheck_hf,
    } = view;

    // Extract evals and points before consuming each sumcheck view.
    let f_at_p1 = sumcheck_fg.out_claim.component_evals[0][0].clone();
    let g_at_p1 = sumcheck_fg.out_claim.component_evals[0][1].clone();
    let point_p1 = Point::from(sumcheck_fg.out_claim.point.clone());
    let claimed_eval_fg = sumcheck_fg.out_claim.claimed_eval.clone();

    let g_at_p2 = sumcheck_gh.out_claim.component_evals[0][0].clone();
    let h_at_p2 = sumcheck_gh.out_claim.component_evals[0][1].clone();
    let point_p2 = Point::from(sumcheck_gh.out_claim.point.clone());
    let claimed_eval_gh = sumcheck_gh.out_claim.claimed_eval.clone();

    let h_at_p3 = sumcheck_hf.out_claim.component_evals[0][0].clone();
    let f_at_p3 = sumcheck_hf.out_claim.component_evals[0][1].clone();
    let point_p3 = Point::from(sumcheck_hf.out_claim.point.clone());
    let claimed_eval_hf = sumcheck_hf.out_claim.claimed_eval.clone();

    let in_fg = SumcheckInputClaim::from_value(claim_fg);
    let in_gh = SumcheckInputClaim::from_value(claim_gh);
    let in_hf = SumcheckInputClaim::from_value(claim_hf);
    sumcheck_fg.build_constraints(&in_fg, ctx).expect("sumcheck fg build_constraints failed");
    sumcheck_gh.build_constraints(&in_gh, ctx).expect("sumcheck gh build_constraints failed");
    sumcheck_hf.build_constraints(&in_hf, ctx).expect("sumcheck hf build_constraints failed");

    // Multiplicative constraints: f(p_i) * g/h(p_i) = claimed_eval_i.
    ctx.assert_a_times_b_equals_c(f_at_p1.clone(), g_at_p1.clone(), claimed_eval_fg).unwrap();
    ctx.assert_a_times_b_equals_c(g_at_p2.clone(), h_at_p2.clone(), claimed_eval_gh).unwrap();
    ctx.assert_a_times_b_equals_c(h_at_p3.clone(), f_at_p3.clone(), claimed_eval_hf).unwrap();

    // Per-commit multi-point openings: f at {p1, p3}, g at {p1, p2}, h at {p2, p3}.
    ctx.assert_mle_eval(oracle_f.clone(), point_p1.clone(), f_at_p1);
    ctx.assert_mle_eval(oracle_f, point_p3.clone(), f_at_p3);
    ctx.assert_mle_eval(oracle_g.clone(), point_p1, g_at_p1);
    ctx.assert_mle_eval(oracle_g, point_p2.clone(), g_at_p2);
    ctx.assert_mle_eval(oracle_h.clone(), point_p2, h_at_p2);
    ctx.assert_mle_eval(oracle_h, point_p3, h_at_p3);
}

#[allow(clippy::too_many_arguments)]
pub fn sumcheck_triple_hadamard_prove<C, RNG>(
    ctx: &mut C,
    num_encoding_variables: u32,
    log_num_polynomials: u32,
    mle_f: Mle<C::Field>,
    mle_g: Mle<C::Field>,
    mle_h: Mle<C::Field>,
    product_fg: HadamardProduct<C::Field, C::Extension>,
    product_gh: HadamardProduct<C::Field, C::Extension>,
    product_hf: HadamardProduct<C::Field, C::Extension>,
    claim_fg: C::Extension,
    claim_gh: C::Extension,
    claim_hf: C::Extension,
    rng: &mut RNG,
) -> SumcheckTripleHadamardView<C>
where
    C: SendingCtx,
    RNG: rand::CryptoRng + rand::Rng,
    rand::distributions::Standard: rand::distributions::Distribution<C::Field>,
{
    let oracle_f = ctx.commit_mle(mle_f, log_num_polynomials, rng).expect("commit f failed");
    let oracle_g = ctx.commit_mle(mle_g, log_num_polynomials, rng).expect("commit g failed");
    let oracle_h = ctx.commit_mle(mle_h, log_num_polynomials, rng).expect("commit h failed");
    let num_vars = num_encoding_variables + log_num_polynomials;
    let param = SumcheckParam::with_component_evals(num_vars, 2, 2);
    let sumcheck_fg = param.prove(&SumcheckInputClaim::from_value(claim_fg), product_fg, ctx);
    let sumcheck_gh = param.prove(&SumcheckInputClaim::from_value(claim_gh), product_gh, ctx);
    let sumcheck_hf = param.prove(&SumcheckInputClaim::from_value(claim_hf), product_hf, ctx);
    SumcheckTripleHadamardView {
        oracle_f,
        oracle_g,
        oracle_h,
        sumcheck_fg,
        sumcheck_gh,
        sumcheck_hf,
    }
}

// ============================================================================
// Scenario #4: RLC-batched single-MLE sumcheck + N PCS evals at the same point.
//
// Commit N independent MLEs, batch their individual hypercube sums into one
// sumcheck via `SumcheckParam::prove_batched` with a challenger-sampled
// `lambda`, and discharge the N per-MLE eval claims together through a single
// `assert_mle_multi_eval` at the shared sumcheck point.
// ============================================================================

pub struct SumcheckBatchedSingleMlesView<C: ConstraintCtx> {
    pub oracles: Vec<C::MleOracle>,
    pub lambda: C::Challenge,
    pub sumcheck_view: SumcheckView<C>,
}

pub fn sumcheck_batched_single_mles_read<C: ReadingCtx>(
    ctx: &mut C,
    num_encoding_variables: u32,
    log_num_polynomials: u32,
    num_claims: usize,
) -> SumcheckBatchedSingleMlesView<C> {
    let oracles: Vec<_> = (0..num_claims)
        .map(|_| {
            ctx.read_oracle(num_encoding_variables, log_num_polynomials)
                .expect("read_oracle failed")
        })
        .collect();
    // Sample the RLC coefficient *after* all oracle commits have been observed.
    let lambda = ctx.sample();
    let num_vars = num_encoding_variables + log_num_polynomials;
    let param = SumcheckParam::with_poly_component_counts(num_vars, 1, vec![1; num_claims]);
    let sumcheck_view = param.read(ctx).expect("sumcheck read failed");
    SumcheckBatchedSingleMlesView { oracles, lambda, sumcheck_view }
}

pub fn sumcheck_batched_single_mles_build_constraints<C: ConstraintCtx>(
    view: SumcheckBatchedSingleMlesView<C>,
    ctx: &mut C,
    claims: &[C::Extension],
) {
    let SumcheckBatchedSingleMlesView { oracles, lambda, sumcheck_view } = view;
    assert_eq!(oracles.len(), claims.len());

    let point = Point::from(sumcheck_view.out_claim.point.clone());
    let per_mle_evals: Vec<C::Expr> =
        sumcheck_view.out_claim.component_evals.iter().map(|v| v[0].clone()).collect();

    let in_claims: Vec<SumcheckInputClaim<C>> =
        claims.iter().map(|c| SumcheckInputClaim::from_value(*c)).collect();
    sumcheck_view
        .build_constraints_batched(&in_claims, lambda, ctx)
        .expect("sumcheck build_constraints failed");

    // Batch all MLE evals at the shared point in one multi-eval group.
    let claims_vec: Vec<_> = oracles.into_iter().zip(per_mle_evals).collect();
    ctx.assert_mle_multi_eval(claims_vec, point);
}

pub fn sumcheck_batched_single_mles_prove<C, RNG>(
    ctx: &mut C,
    num_encoding_variables: u32,
    log_num_polynomials: u32,
    originals: Vec<Mle<C::Field>>,
    mles_ef: Vec<Mle<C::Extension>>,
    claims: &[C::Extension],
    rng: &mut RNG,
) -> SumcheckBatchedSingleMlesView<C>
where
    C: SendingCtx,
    RNG: rand::CryptoRng + rand::Rng,
    rand::distributions::Standard: rand::distributions::Distribution<C::Field>,
{
    assert_eq!(originals.len(), mles_ef.len());
    assert_eq!(originals.len(), claims.len());

    let oracles: Vec<_> = originals
        .into_iter()
        .map(|mle| ctx.commit_mle(mle, log_num_polynomials, rng).expect("commit failed"))
        .collect();
    // Sample the RLC coefficient *after* all oracle commits have been observed.
    let lambda = ctx.sample();
    let num_vars = num_encoding_variables + log_num_polynomials;
    let num_claims = claims.len();
    let param = SumcheckParam::with_poly_component_counts(num_vars, 1, vec![1; num_claims]);

    let in_claims: Vec<SumcheckInputClaim<C>> =
        claims.iter().map(|c| SumcheckInputClaim::from_value(*c)).collect();
    let sumcheck_view = param.prove_batched(&in_claims, lambda.into(), mles_ef, ctx);

    SumcheckBatchedSingleMlesView { oracles, lambda, sumcheck_view }
}

// ============================================================================
// Shared test-data generators
// ============================================================================

/// Generate a random MLE in `F`, its lift to `EF`, and its hypercube sum (the
/// basic-sumcheck claim).
pub fn generate_random_single_mle<F, EF>(
    rng: &mut impl rand::Rng,
    num_vars: u32,
) -> (Mle<F>, Mle<EF>, EF)
where
    F: Field,
    EF: AbstractExtensionField<F> + AbstractField + Copy + Send + Sync + 'static,
    rand::distributions::Standard: rand::distributions::Distribution<F>,
{
    let original = Mle::<F>::rand(rng, 1, num_vars);
    let ef_data: Vec<EF> = original.guts().as_slice().iter().map(|&x| EF::from(x)).collect();
    let mle_ef = Mle::new(RowMajorMatrix::new(ef_data, 1).into());
    let claim: EF = original.guts().as_slice().iter().copied().sum::<F>().into();
    (original, mle_ef, claim)
}

/// Generate a random Hadamard-product sumcheck instance over `num_vars`
/// variables. Returns the two base-field MLE factors, the combined
/// `HadamardProduct` polynomial, and the matching hypercube sum.
pub fn generate_random_hadamard_product<F, EF>(
    rng: &mut impl rand::Rng,
    num_vars: u32,
) -> (Mle<F>, Mle<F>, HadamardProduct<F, EF>, EF)
where
    F: Field,
    EF: AbstractExtensionField<F> + AbstractField + Copy + Send + Sync + 'static,
    rand::distributions::Standard: rand::distributions::Distribution<F>,
{
    let mle_base = Mle::<F>::rand(rng, 1, num_vars);
    let mle_ext = Mle::<F>::rand(rng, 1, num_vars);

    let ext_ef_data: Vec<EF> = mle_ext.guts().as_slice().iter().map(|&x| EF::from(x)).collect();
    let mle_ext_as_ef = Mle::new(RowMajorMatrix::new(ext_ef_data, 1).into());

    let long_base = LongMle::from_components(vec![mle_base.clone()], num_vars);
    let long_ext = LongMle::from_components(vec![mle_ext_as_ef], num_vars);
    let product = HadamardProduct { base: long_base, ext: long_ext };

    let claim: EF = mle_base
        .guts()
        .as_slice()
        .iter()
        .zip(mle_ext.guts().as_slice().iter())
        .map(|(&b, &e)| EF::from(b) * EF::from(e))
        .sum();

    (mle_base, mle_ext, product, claim)
}
