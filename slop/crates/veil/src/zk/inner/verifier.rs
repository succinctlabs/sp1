use std::sync::{Arc, Mutex, MutexGuard};

use crate::compiler::TranscriptReadError;
use crate::zk::dot_product::{dot_product, verify_zk_dot_product, ZkDotProductError};
use crate::zk::error_correcting_code::RsFromCoefficients;
use crate::zk::hadamard_product::{verify_zk_hadamard_and_dots, ZkHadamardAndDotsError};
use derive_where::derive_where;
use slop_algebra::AbstractField;
use slop_challenger::{CanObserve, FieldChallenger};
use slop_commit::Rounds;
use thiserror::Error;

use super::prover::{ZkCnstrProof, ZkMulCnstrProof, ZkProof};
use super::transcript::{
    MleCommitmentIndex, PcsCommitmentEntry, Point, ProofTranscript, TranscriptLinConstraint,
    TranscriptMulConstraint,
};
use super::verifier_transcript::{VerifierElement, VerifierLinExpression, VerifierValue};
use super::{
    ConstraintContextInner, ConstraintContextInnerExt, ExpressionIndex, ZkCnstrAndReadingCtxInner,
    ZkExpression, ZkIopCtx, ZkPcsVerificationError, ZkPcsVerifier,
};

/// Handle to a [`ZkVerificationContextInner`] that provides shared mutable access.
/// This is the main type users interact with for verifying zero-knowledge proofs.
///
/// The handle wraps the inner context in `Arc<Mutex<>>` to allow elements
/// to hold references back to the context, while remaining `Send + Sync`.
///
/// # Type Parameters
/// * `GC` - The ZK IOP context type.
/// * `P` - The PCS proof wire format (threaded explicitly; `()` when no PCS is used).
///
/// Contains a challenger which can be accessed using self.borrow_mut().challenger
#[derive_where(Clone)]
pub struct ZkVerificationContext<GC: ZkIopCtx, P = ()> {
    inner: Arc<Mutex<ZkVerificationContextInner<GC, P>>>,
}

/// Verification context that accumulates constraints during verification.
///
/// This struct maintains mutable state during verification, reading proof values
/// and accumulating linear and multiplicative constraints.
///
/// # Type Parameters
/// * `GC` - The ZK IOP context type.
/// * `P` - The PCS proof wire format (threaded explicitly; `()` when no PCS is used).
#[derive_where(Clone; P)]
pub struct ZkVerificationContextInner<GC: ZkIopCtx, P = ()> {
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

    /// Cursor into `proof.pcs_proofs`, advanced once per eager MLE-eval verification.
    pcs_proof_cursor: usize,

    /// The stored constraint proof
    proof: ZkCnstrProof<GC, P>,
}

impl<GC: ZkIopCtx, P> super::constraints::private::Sealed for ZkVerificationContext<GC, P> {}

impl<GC: ZkIopCtx, P> ConstraintContextInner<GC::EF> for ZkVerificationContext<GC, P> {
    type Element = VerifierElement<GC::EF>;
    type Challenger = GC::Challenger;

    fn with_challenger_inner<R>(&mut self, f: impl FnOnce(&mut GC::Challenger) -> R) -> R {
        f(&mut self.borrow_mut().challenger)
    }

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
    ) -> VerifierValue<GC, P> {
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

    fn commitment_log_num_cols(&self, index: MleCommitmentIndex) -> usize {
        self.borrow().pcs_commitment_transcript[index.index()].log_num_polys
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
    #[error("MLE-eval opening asserted but no PCS verifier was provided")]
    NoPcsVerifier,
}

impl<GC: ZkIopCtx, P> ZkProof<GC, P> {
    /// Opens a zkproof for verification.
    ///
    /// Returns an initialized mutable [`ZkVerificationContext`] containing the proof.
    ///
    /// Creates a default challenger internally and observes the mask commitment.
    pub(crate) fn open(self) -> ZkVerificationContext<GC, P> {
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
            pcs_proof_cursor: 0,
            proof: self.proof,
        };

        ZkVerificationContext { inner: Arc::new(Mutex::new(inner)) }
    }
}

impl<GC: ZkIopCtx, P> ZkVerificationContext<GC, P> {
    /// Lock the inner context mutably and return a guard.
    pub fn borrow_mut(&self) -> MutexGuard<'_, ZkVerificationContextInner<GC, P>> {
        self.inner.lock().expect("ZkVerificationContext mutex poisoned")
    }

    /// Lock the inner context and return a guard.
    pub fn borrow(&self) -> MutexGuard<'_, ZkVerificationContextInner<GC, P>> {
        self.inner.lock().expect("ZkVerificationContext mutex poisoned")
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

    /// Eagerly verifies a (possibly batched) MLE-eval opening at `reduced_point` and returns the
    /// per-commitment column sub-evaluation expressions. The caller asserts how those columns
    /// combine into each claimed evaluation.
    ///
    /// Consumes the next proof from `proof.pcs_proofs` (openings are verified in the same order the
    /// prover produced them) and reads the opening's transcript messages, advancing the Fiat-Shamir
    /// challenger over them. Must only be called once the main protocol transcript is exhausted —
    /// i.e. openings are terminal.
    #[allow(clippy::type_complexity)]
    pub(in crate::zk) fn verify_mle_eval<V>(
        &mut self,
        pcs_verifier: &V,
        commitment_indices: Rounds<MleCommitmentIndex>,
        reduced_point: &Point<GC::EF>,
    ) -> Result<Rounds<Vec<VerifierValue<GC, P>>>, ZkVerifierError>
    where
        V: ZkPcsVerifier<GC, Proof = P>,
        P: Clone,
    {
        let cursor = self.borrow().pcs_proof_cursor;
        let proof = {
            let inner = self.borrow();
            inner.proof.pcs_proofs.get(cursor).cloned().ok_or(
                ZkVerifierError::PcsProofCountMismatch {
                    expected: cursor + 1,
                    actual: inner.proof.pcs_proofs.len(),
                },
            )?
        };
        self.borrow_mut().pcs_proof_cursor += 1;

        pcs_verifier
            .verify_multi_eval(self, commitment_indices, reduced_point, &proof)
            .map_err(|error| ZkVerifierError::PcsVerificationFailed { index: cursor, error })
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
    /// PCS evaluation proofs are verified eagerly at each `assert_mle_eval` (see
    /// [`Self::verify_mle_eval`]), so this only discharges the linear and multiplicative
    /// constraints. It does check that every PCS proof carried in the proof was consumed by an
    /// opening.
    pub fn verify(mut self) -> Result<(), ZkVerifierError>
    where
        GC: ZkIopCtx,
        P: Clone,
    {
        // Every PCS proof must have been consumed by a (terminal) eager opening.
        {
            let inner = self.borrow();
            let consumed = inner.pcs_proof_cursor;
            let available = inner.proof.pcs_proofs.len();
            if consumed != available {
                return Err(ZkVerifierError::PcsProofCountMismatch {
                    expected: consumed,
                    actual: available,
                });
            }
        }

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
        let mut inner = match Arc::try_unwrap(self.inner) {
            Ok(mutex) => mutex.into_inner().expect("ZkVerificationContext mutex poisoned"),
            Err(arc) => {
                eprintln!(
                    "WARNING: ZkVerificationContext has outstanding references (likely from VerifierElements). \
                     Cloning inner context. Consider dropping VerifierElements before calling verify."
                );
                arc.lock().expect("ZkVerificationContext mutex poisoned").clone()
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

impl<GC: ZkIopCtx, P> ZkCnstrAndReadingCtxInner<GC> for ZkVerificationContext<GC, P> {
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
