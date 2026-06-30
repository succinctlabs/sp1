//! End-to-end test scenarios, written generically over `SendingCtx` /
//! `ReadingCtx`. Each backend's `tests.rs` wraps these with concrete context
//! init + finalize.
//!
//! Per scenario, two symmetric pieces:
//!
//! - `*_prove`  — prover side: emit the transcript (no constraints).
//! - `*_verify` — read transcript + emit constraints, in one `ReadingCtx`-generic
//!   pass. Run unchanged on the verifier and (via the prover's replay
//!   `ReadingCtx`) on the prover.
//!
//! The concrete per-backend test files call them as
//! `prove → verify → ctx.prove() / ctx.verify()` on each side. The ZK backend's
//! [`compute_mask_length`](slop_veil::zk::compute_mask_length) consumes the
//! `*_verify` function directly.

use std::sync::Arc;

use rand::distributions::{Distribution, Standard};
use rand::{CryptoRng, Rng};
use slop_algebra::{AbstractExtensionField, AbstractField, Field};
use slop_commit::Message;
use slop_jagged::{HadamardProduct, LongMle};
use slop_matrix::dense::RowMajorMatrix;
use slop_multilinear::{Mle, Point};
use slop_stacked::stack_multilinear;
use slop_sumcheck::SumcheckPolyFirstRound;

use slop_veil::compiler::{ReadingCtx, SendingCtx};
use slop_veil::protocols::sumcheck::{SumcheckInputClaim, SumcheckParam};
use slop_veil::protocols::ProtocolError;

// ============================================================================
// Scenario #1: Hadamard-product sumcheck, no PCS.
//
// Sumcheck a degree-2 product of two multilinears over `num_vars` variables,
// emit only round-consistency constraints. No oracles, no PCS.
// ============================================================================

pub fn sumcheck_no_pcs_prove<C, P>(ctx: &mut C, num_variables: u32, poly: P, claim: C::Extension)
where
    C: SendingCtx,
    P: SumcheckPolyFirstRound<C::Extension>,
{
    let in_claim = SumcheckInputClaim::from_value(claim);
    SumcheckParam::with_component_evals(num_variables, 2, 2).prove(&in_claim, poly, ctx);
}

pub fn sumcheck_no_pcs_verify<C: ReadingCtx>(
    ctx: &mut C,
    num_variables: u32,
    claim: C::Extension,
) -> Result<(), ProtocolError<C::AssertError>> {
    let in_claim = SumcheckInputClaim::from_value(claim);
    SumcheckParam::with_component_evals(num_variables, 2, 2).verify(&in_claim, ctx)?;
    Ok(())
}

// ============================================================================
// Scenario #2: single-MLE sumcheck + 1 PCS eval.
// ============================================================================

pub fn sumcheck_single_mle_prove<C, RNG>(
    ctx: &mut C,
    num_variables: u32,
    original_mle: Mle<C::Field>,
    mle_ef: Mle<C::Extension>,
    claim: C::Extension,
    rng: &mut RNG,
) where
    C: SendingCtx,
    RNG: CryptoRng + Rng,
    Standard: Distribution<C::Field>,
{
    let enc = ctx.num_encoding_variables();
    ctx.commit_mle(stack_multilinear(original_mle, enc), rng).expect("commit_mle failed");
    let in_claim = SumcheckInputClaim::from_value(claim);
    SumcheckParam::new(num_variables, 1).prove(&in_claim, mle_ef, ctx);
}

pub fn sumcheck_single_mle_verify<C: ReadingCtx>(
    ctx: &mut C,
    num_variables: u32,
    claim: C::Extension,
) -> Result<(), ProtocolError<C::AssertError>> {
    let oracle = ctx.read_oracle(num_variables).ok_or(ProtocolError::MissingOracle)?;
    let in_claim = SumcheckInputClaim::from_value(claim);
    let out_claim = SumcheckParam::new(num_variables, 1).verify(&in_claim, ctx)?;
    let point = Point::from(out_claim.point.clone());
    ctx.assert_mle_eval(oracle, &point, out_claim.claimed_eval).map_err(ProtocolError::Assert)
}

/// Splits a flat MLE into `num_components` pre-stacked block-column components (contiguous block
/// ranges), as a multi-component producer (e.g. jagged) would hand to the commit. Their columns
/// concatenate, in order, into the full block-column set.
fn split_into_components<F: Field>(
    flat: &Mle<F>,
    num_encoding_variables: u32,
    num_components: usize,
) -> Message<Mle<F>> {
    let data = flat.guts().as_slice();
    assert_eq!(data.len() % num_components, 0);
    let per = data.len() / num_components;
    let mut components: Vec<Arc<Mle<F>>> = Vec::with_capacity(num_components);
    for k in 0..num_components {
        let sub = Mle::from(data[k * per..(k + 1) * per].to_vec());
        components.extend(stack_multilinear(sub, num_encoding_variables));
    }
    Message::from(components)
}

/// Like [`sumcheck_single_mle_prove`], but commits the oracle as `num_components` separate
/// pre-stacked data components under a single commitment (the "longer message" path). The verify
/// side is component-agnostic, so [`sumcheck_single_mle_verify`] is reused unchanged.
#[allow(clippy::too_many_arguments)]
pub fn sumcheck_single_mle_multi_component_prove<C, RNG>(
    ctx: &mut C,
    num_variables: u32,
    original_mle: Mle<C::Field>,
    mle_ef: Mle<C::Extension>,
    claim: C::Extension,
    num_components: usize,
    rng: &mut RNG,
) where
    C: SendingCtx,
    RNG: CryptoRng + Rng,
    Standard: Distribution<C::Field>,
{
    let enc = ctx.num_encoding_variables();
    let components = split_into_components(&original_mle, enc, num_components);
    ctx.commit_mle(components, rng).expect("commit_mle failed");
    let in_claim = SumcheckInputClaim::from_value(claim);
    SumcheckParam::new(num_variables, 1).prove(&in_claim, mle_ef, ctx);
}

// ============================================================================
// Scenario #3: Hadamard-product sumcheck + 2 PCS evals at the same point.
// ============================================================================

#[allow(clippy::too_many_arguments)]
pub fn sumcheck_hadamard_prove<C, RNG>(
    ctx: &mut C,
    num_variables: u32,
    mle_base: Mle<C::Field>,
    mle_ext: Mle<C::Field>,
    product: HadamardProduct<C::Field, C::Extension>,
    claim: C::Extension,
    rng: &mut RNG,
) where
    C: SendingCtx,
    RNG: CryptoRng + Rng,
    Standard: Distribution<C::Field>,
{
    let enc = ctx.num_encoding_variables();
    ctx.commit_mle(stack_multilinear(mle_base, enc), rng).expect("commit base failed");
    ctx.commit_mle(stack_multilinear(mle_ext, enc), rng).expect("commit ext failed");
    let in_claim = SumcheckInputClaim::from_value(claim);
    SumcheckParam::with_component_evals(num_variables, 2, 2).prove(&in_claim, product, ctx);
}

pub fn sumcheck_hadamard_verify<C: ReadingCtx>(
    ctx: &mut C,
    num_variables: u32,
    claim: C::Extension,
) -> Result<(), ProtocolError<C::AssertError>> {
    let oracle_base = ctx.read_oracle(num_variables).ok_or(ProtocolError::MissingOracle)?;
    let oracle_ext = ctx.read_oracle(num_variables).ok_or(ProtocolError::MissingOracle)?;
    let in_claim = SumcheckInputClaim::from_value(claim);
    let out_claim =
        SumcheckParam::with_component_evals(num_variables, 2, 2).verify(&in_claim, ctx)?;
    let point = Point::from(out_claim.point.clone());
    let base_eval = out_claim.component_evals[0][0].clone();
    let ext_eval = out_claim.component_evals[0][1].clone();
    ctx.assert_a_times_b_equals_c(base_eval.clone(), ext_eval.clone(), out_claim.claimed_eval)
        .map_err(ProtocolError::Assert)?;
    // Batch both oracles at the shared sumcheck point into a single multi-eval
    // group → one PCS proof covering both commits.
    ctx.assert_mle_multi_eval(vec![(oracle_base, base_eval), (oracle_ext, ext_eval)], &point)
        .map_err(ProtocolError::Assert)
}

// ============================================================================
// Scenario #4: RLC-batched single-MLE sumcheck + N PCS evals at the same point.
//
// Sample the RLC `lambda` *after* all oracle commits have been observed (on
// both sides), batch the N hypercube sums into one sumcheck via
// `prove_batched`/`verify_batched`, and discharge the N per-MLE eval claims
// together through a single `assert_mle_multi_eval` at the shared point.
// ============================================================================

pub fn sumcheck_batched_single_mles_prove<C, RNG>(
    ctx: &mut C,
    num_variables: u32,
    originals: Vec<Mle<C::Field>>,
    mles_ef: Vec<Mle<C::Extension>>,
    claims: &[C::Extension],
    rng: &mut RNG,
) where
    C: SendingCtx,
    RNG: CryptoRng + Rng,
    Standard: Distribution<C::Field>,
{
    assert_eq!(originals.len(), mles_ef.len());
    assert_eq!(originals.len(), claims.len());

    let enc = ctx.num_encoding_variables();
    for mle in originals {
        ctx.commit_mle(stack_multilinear(mle, enc), rng).expect("commit failed");
    }
    let lambda = ctx.sample();
    let num_claims = claims.len();
    let in_claims: Vec<SumcheckInputClaim<C>> =
        claims.iter().map(|c| SumcheckInputClaim::from_value(*c)).collect();
    SumcheckParam::with_poly_component_counts(num_variables, 1, vec![1; num_claims]).prove_batched(
        &in_claims,
        lambda.into(),
        mles_ef,
        ctx,
    );
}

pub fn sumcheck_batched_single_mles_verify<C: ReadingCtx>(
    ctx: &mut C,
    num_variables: u32,
    claims: &[C::Extension],
) -> Result<(), ProtocolError<C::AssertError>> {
    let oracles: Vec<_> = (0..claims.len())
        .map(|_| ctx.read_oracle(num_variables).ok_or(ProtocolError::MissingOracle))
        .collect::<Result<_, _>>()?;
    // Sample the RLC coefficient *after* all oracle commits have been observed.
    let lambda = ctx.sample();
    let in_claims: Vec<SumcheckInputClaim<C>> =
        claims.iter().map(|c| SumcheckInputClaim::from_value(*c)).collect();
    let out_claim =
        SumcheckParam::with_poly_component_counts(num_variables, 1, vec![1; claims.len()])
            .verify_batched(&in_claims, lambda, ctx)?;
    let point = Point::from(out_claim.point.clone());
    let per_mle_evals: Vec<C::Expr> =
        out_claim.component_evals.iter().map(|v| v[0].clone()).collect();
    let claims_vec: Vec<_> = oracles.into_iter().zip(per_mle_evals).collect();
    ctx.assert_mle_multi_eval(claims_vec, &point).map_err(ProtocolError::Assert)
}

// ============================================================================
// Scenario #5: Triple Hadamard, multi-point.
//
// Run three independent Hadamard sumchecks (fg at p1, gh at p2, hf at p3).
// Each commit gets opened at two *different* points — exercising the multi-
// point PCS discharge path. Requires `C::MleOracle: Clone` since each commit is
// handed to two separate `assert_mle_eval` calls.
//
// The ZK backend opens each commitment at most once (a second opening would break
// zero-knowledge), so the second `assert_mle_eval` on the same commit returns
// `ZkProveError::DuplicateEvalClaim`; the ZK facade matches on that error.
// ============================================================================

#[allow(clippy::too_many_arguments)]
pub fn sumcheck_triple_hadamard_prove<C, RNG>(
    ctx: &mut C,
    num_variables: u32,
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
) where
    C: SendingCtx,
    RNG: CryptoRng + Rng,
    Standard: Distribution<C::Field>,
{
    let enc = ctx.num_encoding_variables();
    ctx.commit_mle(stack_multilinear(mle_f, enc), rng).expect("commit f failed");
    ctx.commit_mle(stack_multilinear(mle_g, enc), rng).expect("commit g failed");
    ctx.commit_mle(stack_multilinear(mle_h, enc), rng).expect("commit h failed");
    let param = SumcheckParam::with_component_evals(num_variables, 2, 2);
    param.prove(&SumcheckInputClaim::from_value(claim_fg), product_fg, ctx);
    param.prove(&SumcheckInputClaim::from_value(claim_gh), product_gh, ctx);
    param.prove(&SumcheckInputClaim::from_value(claim_hf), product_hf, ctx);
}

pub fn sumcheck_triple_hadamard_verify<C>(
    ctx: &mut C,
    num_variables: u32,
    claim_fg: C::Extension,
    claim_gh: C::Extension,
    claim_hf: C::Extension,
) -> Result<(), ProtocolError<C::AssertError>>
where
    C: ReadingCtx,
    C::MleCommit: Clone,
{
    let oracle_f = ctx.read_oracle(num_variables).ok_or(ProtocolError::MissingOracle)?;
    let oracle_g = ctx.read_oracle(num_variables).ok_or(ProtocolError::MissingOracle)?;
    let oracle_h = ctx.read_oracle(num_variables).ok_or(ProtocolError::MissingOracle)?;
    let param = SumcheckParam::with_component_evals(num_variables, 2, 2);

    let out_fg = param.verify(&SumcheckInputClaim::from_value(claim_fg), ctx)?;
    let out_gh = param.verify(&SumcheckInputClaim::from_value(claim_gh), ctx)?;
    let out_hf = param.verify(&SumcheckInputClaim::from_value(claim_hf), ctx)?;

    let f_at_p1 = out_fg.component_evals[0][0].clone();
    let g_at_p1 = out_fg.component_evals[0][1].clone();
    let point_p1 = Point::from(out_fg.point.clone());
    let claimed_eval_fg = out_fg.claimed_eval.clone();

    let g_at_p2 = out_gh.component_evals[0][0].clone();
    let h_at_p2 = out_gh.component_evals[0][1].clone();
    let point_p2 = Point::from(out_gh.point.clone());
    let claimed_eval_gh = out_gh.claimed_eval.clone();

    let h_at_p3 = out_hf.component_evals[0][0].clone();
    let f_at_p3 = out_hf.component_evals[0][1].clone();
    let point_p3 = Point::from(out_hf.point.clone());
    let claimed_eval_hf = out_hf.claimed_eval.clone();

    // Multiplicative constraints: f(p_i) * g/h(p_i) = claimed_eval_i.
    ctx.assert_a_times_b_equals_c(f_at_p1.clone(), g_at_p1.clone(), claimed_eval_fg)
        .map_err(ProtocolError::Assert)?;
    ctx.assert_a_times_b_equals_c(g_at_p2.clone(), h_at_p2.clone(), claimed_eval_gh)
        .map_err(ProtocolError::Assert)?;
    ctx.assert_a_times_b_equals_c(h_at_p3.clone(), f_at_p3.clone(), claimed_eval_hf)
        .map_err(ProtocolError::Assert)?;

    // Per-commit multi-point openings: f at {p1, p3}, g at {p1, p2}, h at {p2, p3}.
    ctx.assert_mle_eval(oracle_f, &point_p1, f_at_p1).map_err(ProtocolError::Assert)?;
    ctx.assert_mle_eval(oracle_f, &point_p3, f_at_p3).map_err(ProtocolError::Assert)?;
    ctx.assert_mle_eval(oracle_g, &point_p1, g_at_p1).map_err(ProtocolError::Assert)?;
    ctx.assert_mle_eval(oracle_g, &point_p2, g_at_p2).map_err(ProtocolError::Assert)?;
    ctx.assert_mle_eval(oracle_h, &point_p2, h_at_p2).map_err(ProtocolError::Assert)?;
    ctx.assert_mle_eval(oracle_h, &point_p3, h_at_p3).map_err(ProtocolError::Assert)?;
    Ok(())
}

// ============================================================================
// Shared test-data generators
// ============================================================================

/// Generate a random MLE in `F`, its lift to `EF`, and its hypercube sum (the
/// basic-sumcheck claim).
pub fn generate_random_single_mle<F, EF>(rng: &mut impl Rng, num_vars: u32) -> (Mle<F>, Mle<EF>, EF)
where
    F: Field,
    EF: AbstractExtensionField<F> + AbstractField + Copy + Send + Sync + 'static,
    Standard: Distribution<F>,
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
    rng: &mut impl Rng,
    num_vars: u32,
) -> (Mle<F>, Mle<F>, HadamardProduct<F, EF>, EF)
where
    F: Field,
    EF: AbstractExtensionField<F> + AbstractField + Copy + Send + Sync + 'static,
    Standard: Distribution<F>,
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
