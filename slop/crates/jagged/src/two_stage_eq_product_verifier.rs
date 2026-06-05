//! Verifier for the two-stage-GKR Option 2 sumcheck.
//!
//! The shared proof type [`TwoStageEqProductProof`], the [`TwoStageEqError`]
//! enum, and the [`verify_two_stage_eq_product`] entry point live here; the
//! prover-side machinery is in `two_stage_eq_product_prover.rs`.

use slop_algebra::{AbstractField, ExtensionField, Field};
use slop_challenger::FieldChallenger;
use slop_multilinear::{partial_lagrange, Mle, Point};
use slop_sumcheck::{partially_verify_sumcheck_proof, PartialSumcheckProof, SumcheckError};
use thiserror::Error;

/// Two-stage-GKR Option 2 proof bundle.
///
/// Both stage proofs are emitted as standard slop [`PartialSumcheckProof`]s; the verifier
/// runs them in sequence, checks the stage-1 → stage-2 claim transition via the announced
/// `v` and the sampled ζ''', and finally re-derives the stage-2 eval claim from the K
/// announced `p_k(η)` evaluations.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TwoStageEqProductProof<EF> {
    /// Stage-1 sumcheck proof (degree K_2 + 1, in c variables).
    pub stage1: PartialSumcheckProof<EF>,
    /// The K_2 mid-protocol B_j(ζ'') claims, sent in the clear after stage 1.
    pub v: Vec<EF>,
    /// Stage-2 sumcheck proof (degree K_1 + 1, in c variables).
    pub stage2: PartialSumcheckProof<EF>,
    /// Final K evaluations p_k(η) sent at the end of stage 2 (one per inner factor).
    pub final_evals: Vec<EF>,
}

impl<EF: AbstractField> TwoStageEqProductProof<EF> {
    /// Creates a dummy two-stage proof, structurally valid for downstream
    /// proof-shape consumers (witness encoding, dummy proofs, etc.) but
    /// **never** verifying. ONLY USE THIS FOR TESTING / MOCK PROOFS.
    #[must_use]
    pub fn dummy() -> Self {
        Self {
            stage1: PartialSumcheckProof::dummy(),
            v: Vec::new(),
            stage2: PartialSumcheckProof::dummy(),
            final_evals: Vec::new(),
        }
    }
}

#[derive(Debug, Error)]
pub enum TwoStageEqError<F: Field> {
    #[error("sumcheck error: {0}")]
    Sumcheck(SumcheckError),
    #[error("two-stage eq-product equality check failed, expected: {0}, got: {1}")]
    EqualityCheckMismatch(F, F),
    #[error("two-stage eq-product proof has incorrect shape")]
    IncorrectShape,
}

/// Verify a [`TwoStageEqProductProof`] for the original claim
///
/// ```text
/// ∑_{i ∈ {0,1}^c} eq(zeta, i) · ∏_{k=0..k1·k2} eq(z_k, p_k[i])
/// ```
///
/// where `c = log_num_cols` and the K = `k1·k2` inner factors `p_k` are MLEs over `c`
/// variables.  Both stage transcripts are checked, the stage-1 → stage-2 claim transition
/// is replayed via the in-protocol ζ''' challenge, and the stage-2 eval claim is
/// re-derived from the prover-supplied `final_evals` (= the K `p_k(η)`'s).
///
/// On success, returns `proof.stage1.claimed_sum` — the verified full-hypercube sum proved
/// here — along with the stage-2 sumcheck point `η` and the K `p_k(η)` values in the proof.
pub fn verify_two_stage_eq_product<F, EF, Challenger>(
    proof: &TwoStageEqProductProof<EF>,
    zeta: &Point<EF>,
    z: &[EF],
    k1: usize,
    k2: usize,
    log_num_cols: usize,
    challenger: &mut Challenger,
) -> Result<(EF, Point<EF>, Vec<EF>), TwoStageEqError<EF>>
where
    F: Field,
    EF: ExtensionField<F>,
    Challenger: FieldChallenger<F>,
{
    let k = k1 * k2;
    if proof.v.len() != k2 || proof.final_evals.len() != k || z.len() != k {
        return Err(TwoStageEqError::IncorrectShape);
    }

    // ----- Stage 1: degree (K_2 + 1) in c variables. -----
    let _lambda1: EF = challenger.sample_ext_element();
    let stage1 = &proof.stage1;
    partially_verify_sumcheck_proof(stage1, challenger, log_num_cols, k2 + 1)
        .map_err(TwoStageEqError::Sumcheck)?;
    challenger.observe_ext_element_slice(&proof.v);

    // Stage-1 eval claim consistency: must equal eq(zeta, stage1_point) · ∏_j v_j.
    let eq_zeta_pt: EF = Mle::full_lagrange_eval(&stage1.point_and_eval.0, zeta);
    let prod_v: EF = proof.v.iter().copied().fold(EF::one(), |acc, vj| acc * vj);
    if eq_zeta_pt * prod_v != stage1.point_and_eval.1 {
        return Err(TwoStageEqError::EqualityCheckMismatch(
            eq_zeta_pt * prod_v,
            stage1.point_and_eval.1,
        ));
    }

    // ζ''' challenge → w = partial_lagrange(ζ''') (size k2).
    let log_k2 = k2.trailing_zeros() as usize;
    let zeta_ppp: Vec<EF> = (0..log_k2).map(|_| challenger.sample_ext_element()).collect();
    let w = partial_lagrange::<EF>(&zeta_ppp.into());
    let w_slice = w.as_slice();

    // Stage-1 → stage-2 claim transition: stage2.claimed_sum must equal Σ_j w_j · v_j.
    let stage2_claim: EF =
        w_slice.iter().zip(proof.v.iter()).fold(EF::zero(), |acc, (wj, vj)| acc + *wj * *vj);
    if stage2_claim != proof.stage2.claimed_sum {
        return Err(TwoStageEqError::EqualityCheckMismatch(stage2_claim, proof.stage2.claimed_sum));
    }

    // ----- Stage 2: degree (K_1 + 1) in c variables. -----
    let _lambda2: EF = challenger.sample_ext_element();
    let stage2 = &proof.stage2;
    partially_verify_sumcheck_proof(stage2, challenger, log_num_cols, k1 + 1)
        .map_err(TwoStageEqError::Sumcheck)?;

    challenger.observe_ext_element_slice(&proof.final_evals);

    // Stage-2 eval claim re-derivation:
    //   eq(stage1_point, η) · Σ_j w_j · ∏_{j'} eq(z_{j·k1+j'}, final_evals[j·k1+j']).
    let eq_zpp_eta: EF =
        Mle::full_lagrange_eval(&stage1.point_and_eval.0, &stage2.point_and_eval.0);
    let mut inner_sum = EF::zero();
    for (j, &wj) in w_slice.iter().enumerate().take(k2) {
        let mut prod = EF::one();
        for jp in 0..k1 {
            let kk = j * k1 + jp;
            let zk = z[kk];
            let pk = proof.final_evals[kk];
            let sub_prod = zk * pk;
            prod *= EF::one() + sub_prod + sub_prod - zk - pk;
        }
        inner_sum += wj * prod;
    }
    let expected_stage2_eval = eq_zpp_eta * inner_sum;
    if expected_stage2_eval != stage2.point_and_eval.1 {
        return Err(TwoStageEqError::EqualityCheckMismatch(
            expected_stage2_eval,
            stage2.point_and_eval.1,
        ));
    }

    Ok((stage1.claimed_sum, proof.stage2.point_and_eval.0.clone(), proof.final_evals.clone()))
}
