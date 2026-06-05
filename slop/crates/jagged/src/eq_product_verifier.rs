//! Verifier for the eq-prefixed product sumcheck — the two-stage-GKR Option 1
//! shape.  The prover-side machinery (polynomial state, round-univariate
//! computation, cached Lagrange-to-power matrix, etc.) lives in
//! `eq_product_prover.rs`.
//!
//! Given K base-field MLEs `p_j` over n variables, an extension-field point
//! `ζ ∈ EF^n`, and an extension-field `z ∈ EF^K`, the verifier checks that the
//! prover-supplied [`PartialSumcheckProof`] together with K opening claims
//! `p_j(point)` constitute a valid sumcheck for
//!
//! ```text
//!   ∑_{x ∈ {0,1}^n} eq(ζ, x) · ∏_{j=1..K} eq(z_j, p_j(x)).
//! ```

use slop_algebra::{ExtensionField, Field};
use slop_challenger::FieldChallenger;
use slop_multilinear::{Mle, Point};
use slop_sumcheck::{partially_verify_sumcheck_proof, PartialSumcheckProof, SumcheckError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EqProductError<F: Field> {
    #[error("sumcheck error: {0}")]
    Sumcheck(SumcheckError),
    #[error("eq-product equality check failed, expected: {0}, got: {1}")]
    EqualityCheckMismatch(F, F),
    #[error("eq-product proof has incorrect shape")]
    IncorrectShape,
}

/// Verify a single-poly eq-prefixed product sumcheck transcript and re-derive
/// the final eval claim from the K opening values `p_j(point)`.  The caller is
/// responsible for sourcing `component_evals` (typically via PCS openings of
/// the K committed `p_j`'s at the sumcheck-returned point).
///
/// Matches the prover-side λ sampling done by
/// `reduce_sumcheck_to_evaluation`, so the verifier must use a challenger
/// initialised to the same FS state.
pub fn verify_eq_product<F, EF, Chal>(
    proof: &PartialSumcheckProof<EF>,
    zeta: &Point<EF>,
    z: &[EF],
    component_evals: &[EF],
    k: usize,
    num_variables: usize,
    challenger: &mut Chal,
) -> Result<(), EqProductError<EF>>
where
    F: Field,
    EF: ExtensionField<F>,
    Chal: FieldChallenger<F>,
{
    if z.len() != k || component_evals.len() != k {
        return Err(EqProductError::IncorrectShape);
    }

    let _lambda: EF = challenger.sample_ext_element();

    partially_verify_sumcheck_proof(proof, challenger, num_variables, k + 1)
        .map_err(EqProductError::Sumcheck)?;

    // Re-derive `eq(ζ, point) · ∏_j eq(z_j, p_j(point))` and check it matches
    // the sumcheck's reduced eval claim at `point`.
    let point = &proof.point_and_eval.0;
    let claimed_eval = proof.point_and_eval.1;

    let eq_at_point: EF = Mle::full_lagrange_eval(zeta, point);
    let factor_prod: EF = z
        .iter()
        .zip(component_evals.iter())
        .fold(EF::one(), |acc, (zj, ej)| acc * ((EF::one() - *zj) * (EF::one() - *ej) + *zj * *ej));
    let expected = eq_at_point * factor_prod;

    if expected != claimed_eval {
        return Err(EqProductError::EqualityCheckMismatch(expected, claimed_eval));
    }
    Ok(())
}
