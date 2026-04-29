use std::cell::{Ref, RefCell, RefMut};
use std::rc::Rc;

use crate::compiler::TranscriptReadError;
use crate::zk::dot_product::{dot_product, verify_zk_dot_product, ZkDotProductError};
use crate::zk::error_correcting_code::RsFromCoefficients;
use crate::zk::hadamard_product::{verify_zk_hadamard_and_dots, ZkHadamardAndDotsError};
use slop_algebra::AbstractField;
use slop_challenger::{CanObserve, FieldChallenger};
use thiserror::Error;

use super::prover::{ZkCnstrProof, ZkMulCnstrProof, ZkProof};
use super::transcript::{
    MleCommitmentIndex, PcsCommitmentEntry, PcsMultiEvalClaim, Point, ProofTranscript,
    TranscriptLinConstraint, TranscriptMulConstraint,
};
use super::verifier_transcript::{VerifierElement, VerifierLinExpression, VerifierValue};
use super::{
    ConstraintContextInner, ConstraintContextInnerExt, ExpressionIndex, ZkCnstrAndReadingCtxInner,
    ZkExpression, ZkIopCtx, ZkPcsVerificationError, ZkPcsVerifier,
};

/// Handle to a [`ZkVerificationContextInner`] that provides shared mutable access.
/// This is the main type users interact with for verifying zero-knowledge proofs.
///
/// The handle wraps the inner context in `Rc<RefCell<>>` to allow elements
/// to hold references back to the context.
///
/// # Type Parameters
/// * `GC` - The ZK IOP context type; `GC::PcsProof` is the PCS proof type.
///
/// Contains a challenger which can be accessed using self.borrow_mut().challenger
#[derive(Clone)]
pub struct ZkVerificationContext<GC: ZkIopCtx> {
    inner: Rc<RefCell<ZkVerificationContextInner<GC>>>,
}

/// Verification context that accumulates constraints during verification.
///
/// This struct maintains mutable state during verification, reading proof values
/// and accumulating linear and multiplicative constraints.
///
/// # Type Parameters
/// * `GC` - The ZK IOP context type; `GC::PcsProof` is the PCS proof type.
#[derive(Clone)]
pub struct ZkVerificationContextInner<GC: ZkIopCtx> {
    /// The challenger for Fiat-Shamir
    challenger: GC::Challenger,

    /// Masked Field element messages sent by prover
    transcript: ProofTranscript<GC::EF>,

    values_current_index: usize,

    lin_constraints: Vec<TranscriptLinConstraint<GC::EF>>,

    /// This field is ignored in verification if the corresponding proof has `None` as its mul_proof field
    mul_constraints: Vec<TranscriptMulConstraint<GC::EF>>,

    expressions: Vec<ZkExpression<GC::EF, VerifierElement<GC::EF>>>,

    /// PCS commitment transcript (from proof)
    pcs_commitment_transcript: Vec<PcsCommitmentEntry<GC::Digest>>,

    /// Current index into pcs_commitment_transcript for reading
    pcs_commitment_current_index: usize,

    /// PCS evaluation claims to be verified (each may batch multiple commitments at same point)
    pcs_eval_claims: Vec<PcsMultiEvalClaim<GC::EF, VerifierValue<GC>>>,

    /// The stored constraint proof
    proof: ZkCnstrProof<GC>,
}

impl<GC: ZkIopCtx> super::constraints::private::Sealed for ZkVerificationContext<GC> {}

impl<GC: ZkIopCtx> ConstraintContextInner<GC::EF> for ZkVerificationContext<GC> {
    type Element = VerifierElement<GC::EF>;

    fn add_lin_constraints(
        &mut self,
        constraints: impl IntoIterator<Item = TranscriptLinConstraint<GC::EF>>,
    ) {
        self.borrow_mut().lin_constraints.extend(constraints);
    }

    fn add_mul_constraints(
        &mut self,
        constraints: impl IntoIterator<Item = TranscriptMulConstraint<GC::EF>>,
    ) {
        self.borrow_mut().mul_constraints.extend(constraints);
    }

    fn add_expr(
        &mut self,
        expr: ZkExpression<GC::EF, VerifierElement<GC::EF>>,
    ) -> VerifierValue<GC> {
        self.borrow_mut().expressions.push(expr);
        ExpressionIndex::new(self.borrow().expressions.len() - 1, self.clone())
    }

    fn get_expr(&self, index: usize) -> Option<ZkExpression<GC::EF, VerifierElement<GC::EF>>> {
        self.borrow().expressions.get(index).cloned()
    }

    fn materialize_prod(
        &mut self,
        a: VerifierLinExpression<GC::EF>,
        b: VerifierLinExpression<GC::EF>,
    ) -> Option<VerifierElement<GC::EF>> {
        let index: VerifierElement<GC::EF> = self.read_one_raw().ok()?.into();
        self.constrain_mul_triple(a, b, index);
        Some(index)
    }

    fn add_eval_claim(
        &mut self,
        commitment_indices: Vec<MleCommitmentIndex>,
        point: Point<GC::EF>,
        eval_exprs: Vec<VerifierValue<GC>>,
    ) {
        self.borrow_mut().pcs_eval_claims.push(PcsMultiEvalClaim {
            commitment_indices,
            point,
            eval_exprs,
        });
    }
}

#[derive(Debug, Clone, Error)]
pub enum ZkVerifierError {
    #[error("Inconsistent masked values dot product")]
    LinearConstraintFailure,
    #[error("Inconsistent mask dot product")]
    MaskDotProductProofFailure(ZkDotProductError),
    #[error("Invalid multiplicative constraint proof shape")]
    InvalidMulConstrProofShape,
    #[error("Invalid multiplicative constraint Hadamard and dot products")]
    InvalidHadamardAndDots(ZkHadamardAndDotsError),
    #[error("PCS proof count mismatch: expected {expected}, got {actual}")]
    PcsProofCountMismatch { expected: usize, actual: usize },
    #[error("PCS verification failed for claim {index}: {error}")]
    PcsVerificationFailed { index: usize, error: ZkPcsVerificationError },
}

impl<GC: ZkIopCtx> ZkProof<GC> {
    /// Opens a zkproof for verification.
    ///
    /// Returns an initialized mutable [`ZkVerificationContext`] containing the proof.
    ///
    /// Creates a default challenger internally and observes the mask commitment.
    pub(crate) fn open(self) -> ZkVerificationContext<GC> {
        let mut challenger = GC::default_challenger();
        challenger.observe(self.proof.mask_commitment);

        let inner = ZkVerificationContextInner {
            challenger,
            transcript: self.transcript,
            values_current_index: 1, // Skip constant block
            lin_constraints: vec![],
            mul_constraints: vec![],
            expressions: vec![],
            pcs_commitment_transcript: self.pcs_commitment_transcript,
            pcs_commitment_current_index: 0,
            pcs_eval_claims: vec![],
            proof: self.proof,
        };

        ZkVerificationContext { inner: Rc::new(RefCell::new(inner)) }
    }
}

impl<GC: ZkIopCtx> ZkVerificationContext<GC> {
    /// Borrow the inner context mutably and return a guard.
    pub fn borrow_mut(&self) -> RefMut<'_, ZkVerificationContextInner<GC>> {
        self.inner.borrow_mut()
    }

    /// Borrow the inner context immutably and return a guard.
    pub fn borrow(&self) -> Ref<'_, ZkVerificationContextInner<GC>> {
        self.inner.borrow()
    }

    // Read the next message of expected length, observe it, and return its block index and length.
    // Returns `TranscriptExhausted` if there is no next message, or `TranscriptReadMismatch` if
    // the next message's length doesn't match `expected_length`.
    fn read_raw(&mut self, expected_length: usize) -> Result<(usize, usize), TranscriptReadError> {
        let mut inner = self.borrow_mut();
        let ZkVerificationContextInner { transcript, challenger, values_current_index, .. } =
            &mut *inner;
        let block_index = *values_current_index;
        let vals =
            transcript.get_values(block_index).ok_or(TranscriptReadError::TranscriptExhausted)?;
        if vals.len() != expected_length {
            return Err(TranscriptReadError::TranscriptReadMismatch {
                expected: expected_length,
                got: vals.len(),
            });
        }

        challenger.observe_ext_element_slice(vals);
        *values_current_index += 1;

        Ok((block_index, expected_length))
    }

    // Read the next message of length 1, observe it, and return its index in the transcript.
    // The expected length must be 1, otherwise returns `TranscriptReadMismatch`.
    fn read_one_raw(&mut self) -> Result<[usize; 2], TranscriptReadError> {
        let (block_index, _) = self.read_raw(1)?;
        Ok([block_index, 0])
    }

    /// Returns the index of the next block to be read.
    pub fn next_block_index(&self) -> usize {
        self.borrow().values_current_index
    }

    /// Returns the PCS commitment entries from the proof.
    pub fn pcs_commitments(&self) -> Vec<PcsCommitmentEntry<GC::Digest>> {
        self.borrow().pcs_commitment_transcript.clone()
    }

    /// Returns the PCS evaluation claims registered so far.
    pub fn pcs_eval_claims(&self) -> Vec<PcsMultiEvalClaim<GC::EF, VerifierValue<GC>>> {
        self.borrow().pcs_eval_claims.clone()
    }

    /// Returns the commitment entry for a given commitment index.
    ///
    /// Returns `None` if the commitment index is out of bounds.
    pub fn get_commitment_entry(
        &self,
        index: MleCommitmentIndex,
    ) -> Option<PcsCommitmentEntry<GC::Digest>> {
        self.borrow().pcs_commitment_transcript.get(index.index()).cloned()
    }

    /// Verifies the constraints built up in the context (call after all these are added).
    ///
    /// # Arguments
    /// * `pcs_verifier` - Optional PCS verifier. If provided, verifies evaluation proofs
    ///   for all registered PCS eval claims using proofs from the stored proof.
    ///   If `None` and there are eval claims, returns an error.
    ///
    /// # Type Parameters
    /// * `V` - The PCS verifier type implementing `ZkPcsVerifier<GC>`
    pub fn verify<V>(mut self, pcs_verifier: Option<&V>) -> Result<(), ZkVerifierError>
    where
        GC: ZkIopCtx,
        V: ZkPcsVerifier<GC, Proof = GC::PcsProof>,
    {
        // Handle PCS evaluation claims first
        self.verify_pcs_claims(pcs_verifier)?;

        // Handle multiplicative constraints - extract proof first
        let mul_proof = self.borrow().proof.mul_proof_wrapper.clone();
        self.verify_mul_proof(mul_proof)?;

        // Checking linear constraints
        let rlc_coeff: GC::EF = self.borrow_mut().challenger.sample_ext_element();

        let dot_vec = {
            let inner = self.borrow();
            inner.transcript.generate_rlc_dot_vector(&inner.lin_constraints, rlc_coeff)
        };

        // Extract the inner context, cloning if there are still outstanding references
        // (e.g., from VerifierElements that haven't been dropped yet)
        let mut inner = match Rc::try_unwrap(self.inner) {
            Ok(refcell) => refcell.into_inner(),
            Err(rc) => {
                eprintln!(
                    "WARNING: ZkVerificationContext has outstanding references (likely from VerifierElements). \
                     Cloning inner context. Consider dropping VerifierElements before calling verify."
                );
                rc.borrow().clone()
            }
        };

        if dot_product(&dot_vec, &inner.transcript.values)
            != inner.proof.zk_dot_product_proof.claimed_dot_products()[0]
        {
            return Err(ZkVerifierError::LinearConstraintFailure);
        }

        if let Err(e) = verify_zk_dot_product::<GC, RsFromCoefficients<GC::EF>>(
            &inner.proof.mask_commitment,
            &dot_vec,
            &inner.proof.zk_dot_product_proof,
            &mut inner.challenger,
        ) {
            return Err(ZkVerifierError::MaskDotProductProofFailure(e));
        }
        Ok(())
    }

    /// Helper method to verify PCS evaluation claims.
    ///
    /// One proof is verified per claim. Each claim may batch multiple commitments.
    fn verify_pcs_claims<V>(&mut self, pcs_verifier: Option<&V>) -> Result<(), ZkVerifierError>
    where
        V: ZkPcsVerifier<GC, Proof = GC::PcsProof>,
    {
        let eval_claims = self.pcs_eval_claims();
        let pcs_proofs = self.borrow().proof.pcs_proofs.clone();

        if eval_claims.is_empty() {
            return Ok(());
        }

        let pcs_verifier = pcs_verifier.ok_or(ZkVerifierError::PcsProofCountMismatch {
            expected: eval_claims.len(),
            actual: 0,
        })?;

        // Verify that we have the right number of PCS proofs
        if pcs_proofs.len() != eval_claims.len() {
            return Err(ZkVerifierError::PcsProofCountMismatch {
                expected: eval_claims.len(),
                actual: pcs_proofs.len(),
            });
        }

        // Verify each PCS proof
        for (i, (claim, pcs_proof)) in eval_claims.into_iter().zip(pcs_proofs.iter()).enumerate() {
            pcs_verifier
                .verify_multi_eval(self, claim, pcs_proof)
                .map_err(|e| ZkVerifierError::PcsVerificationFailed { index: i, error: e })?;
        }

        // Clear eval claims to drop VerifierValue references before calling verify
        self.borrow_mut().pcs_eval_claims.clear();

        Ok(())
    }

    /// Helper method to verify multiplicative constraint proofs.
    fn verify_mul_proof(
        &mut self,
        mul_proof: Option<ZkMulCnstrProof<GC>>,
    ) -> Result<(), ZkVerifierError> {
        let Some(mul_proof) = mul_proof else {
            if self.borrow().mul_constraints.is_empty() {
                return Ok(());
            } else {
                return Err(ZkVerifierError::InvalidMulConstrProofShape);
            }
        };

        // Read/observe the 6 padding values and enforce the two tautological mul
        // constraints. The honest prover populates this block with
        // `(r, s, rs, r-1, t, (r-1)t)` for i.i.d. uniform `r, s, t`; we only enforce
        // `r * s = rs` and `(r-1) * t = (r-1)t`, which is all that soundness
        // requires. The structural relation between the two `a` entries (the second
        // equals the first minus one) is needed only for the simulator's bijection
        // in the zero-knowledge argument.
        let [a1, b1, c1, a2, b2, c2]: [_; 6] = self
            .read_next(6)
            .map_err(|_| ZkVerifierError::InvalidMulConstrProofShape)?
            .try_into()
            .unwrap();
        self.constrain_mul_triple(
            a1.try_into_index().unwrap(),
            b1.try_into_index().unwrap(),
            c1.try_into_index().unwrap(),
        );
        self.constrain_mul_triple(
            a2.try_into_index().unwrap(),
            b2.try_into_index().unwrap(),
            c2.try_into_index().unwrap(),
        );

        let mul_len = self.borrow().mul_constraints.len();

        // Sample RLC coefficient (must match prover order)
        let rlc_coeff: GC::EF = {
            let mut inner = self.borrow_mut();
            inner.challenger.sample_ext_element()
        };

        // Compute dot_vec from RLC powers
        let dot_vec: Vec<GC::EF> = rlc_coeff.powers().take(mul_len).collect();

        // Verify combined hadamard + dot product proofs
        if let Err(e) = verify_zk_hadamard_and_dots::<GC, _>(
            &mul_proof.commitment,
            &dot_vec,
            &mul_proof.mul_proof,
            &mut self.borrow_mut().challenger,
        ) {
            return Err(ZkVerifierError::InvalidHadamardAndDots(e));
        }

        // Build and add the new linear constraints that dot product vects picked out correctly
        let new_lin_constraints = {
            let dot_prods: [GC::EF; 3] =
                std::array::from_fn(|i| mul_proof.mul_proof.dot_claimed_dot_products()[i]);
            let inner = self.borrow();
            inner.transcript.pickout_lin_constraints_from_mul_constraints(
                &inner.mul_constraints,
                &dot_prods,
                rlc_coeff,
            )
        };
        self.add_lin_constraints(new_lin_constraints.to_vec());

        Ok(())
    }
}

/// A no-op PCS verifier for when no PCS is needed.
///
/// This type is used as a default when calling `verify` without PCS support.
#[derive(Clone, Copy, Debug)]
pub struct NoPcsVerifier;

impl<GC: ZkIopCtx> ZkPcsVerifier<GC> for NoPcsVerifier {
    type Proof = GC::PcsProof;

    fn verify_multi_eval(
        &self,
        _ctx: &mut ZkVerificationContext<GC>,
        _claim: PcsMultiEvalClaim<GC::EF, VerifierValue<GC>>,
        _proof: &GC::PcsProof,
    ) -> Result<(), ZkPcsVerificationError> {
        panic!("NoPcsVerifier::verify_multi_eval should never be called")
    }
}

impl<GC: ZkIopCtx> ZkVerificationContext<GC> {
    /// Convenience method to verify a proof without PCS support.
    ///
    /// This only verifies the linear and multiplicative constraints.
    ///
    /// # Errors
    /// Returns an error if there are any PCS evaluation claims registered
    /// (use `verify` with a PCS verifier instead).
    pub fn verify_without_pcs(self) -> Result<(), ZkVerifierError>
    where
        GC: ZkIopCtx,
    {
        self.verify::<NoPcsVerifier>(None)
    }
}

impl<GC: ZkIopCtx> ZkCnstrAndReadingCtxInner<GC> for ZkVerificationContext<GC> {
    /// Receives the next message of length 1, observes it, and outputs a single [`ExpressionIndex`].
    ///
    /// Errors if the transcript is exhausted or the message length isn't 1.
    fn read_one(
        &mut self,
    ) -> Result<<Self as ConstraintContextInnerExt<GC::EF>>::Expr, TranscriptReadError> {
        let idx = self.read_one_raw()?;
        Ok(self.add_expr(idx.into()))
    }

    /// Receives the next message, observes it, and outputs [`ExpressionIndex`]es.
    ///
    /// Errors if the transcript is exhausted or the message length doesn't match `num`.
    fn read_next(
        &mut self,
        num: usize,
    ) -> Result<Vec<<Self as ConstraintContextInnerExt<GC::EF>>::Expr>, TranscriptReadError> {
        let (block_index, len) = self.read_raw(num)?;
        Ok((0..len).map(|i| self.add_expr([block_index, i].into())).collect())
    }

    fn challenger(&mut self) -> RefMut<'_, GC::Challenger> {
        RefMut::map(self.borrow_mut(), |inner| &mut inner.challenger)
    }

    fn read_next_pcs_commitment(
        &mut self,
        num_vars: usize,
        log_num_polys: usize,
    ) -> Option<MleCommitmentIndex> {
        let mut inner = self.borrow_mut();
        let idx = inner.pcs_commitment_current_index;

        let entry = inner.pcs_commitment_transcript.get(idx)?;

        // Verify parameters match
        if entry.num_vars != num_vars || entry.log_num_polys != log_num_polys {
            return None;
        }

        // Observe the commitment digest in the Fiat-Shamir challenger
        let digest = entry.digest;
        inner.challenger.observe(digest);

        // Advance the index
        inner.pcs_commitment_current_index += 1;

        Some(MleCommitmentIndex::new(idx))
    }
}

#[derive(Debug, Eq, PartialEq, Error)]
#[error("invalid proof shape")]
pub struct ZKProtocolShapeError;

/// Trait for protocol parameters that know how to read proof values from transcript.
///
/// This trait is implemented on protocol parameter structs and produces
/// self-contained proof structs that include the parameters.
///
/// The returned proof contains `VerifierElement<GC>` since `read_proof_from_transcript`
/// reads from the verifier context.
pub trait ZkProtocolParameters<GC: ZkIopCtx, C: ZkCnstrAndReadingCtxInner<GC>> {
    /// The proof type produced by reading from transcript.
    /// Must implement `ZkProtocolProof` so it can generate its own constraints.
    type Proof: ZkProtocolProof<GC, C>;

    /// Reads proof values from transcript, reconstructs Fiat-Shamir state,
    /// and returns a self-contained proof that includes these parameters.
    fn read_proof_from_transcript(&self, context: &mut C) -> Option<Self::Proof>;
}

/// Trait for self-contained proofs that can generate their own constraints.
///
/// Proofs implementing this trait contain all necessary data (including parameters)
/// to generate linear constraints without additional inputs.
///
/// Generic over ConstraintContextOuter to be uniform across prover and verifier.
pub trait ZkProtocolProof<GC: ZkIopCtx, C: ConstraintContextInnerExt<GC::EF>>:
    std::fmt::Debug + Clone
{
    /// Builds and asserts constraints for this proof using the element's expression type.
    ///
    /// This method consumes `self` to ensure all stored elements are dropped after
    /// building constraints, which releases references to the context.
    fn build_constraints(self);
}
