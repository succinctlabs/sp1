use std::{
    error::Error,
    fmt::Debug,
    ops::{Deref, DerefMut},
};

use crate::{Mle, MleEval, Point};
use derive_where::derive_where;
use serde::{de::DeserializeOwned, Serialize};
use slop_algebra::{ExtensionField, Field};
use slop_alloc::{Backend, CpuBackend, HasBackend};
use slop_challenger::{FieldChallenger, IopCtx};
use slop_commit::{Message, Rounds};

#[derive(Debug, Clone)]
#[derive_where(PartialEq, Eq, Serialize, Deserialize; MleEval<F, A>)]
pub struct Evaluations<F, A: Backend = CpuBackend> {
    pub round_evaluations: Vec<MleEval<F, A>>,
}

/// A verifier of a multilinear commitment scheme.
///
/// A verifier for a multilinear commitment scheme (or PCS) is a protocol that enables getting
/// succinct commitments representing multilinear polynomials and later making query checks for
/// their evaluation.
///
/// The verifier described by this trait supports compiling a multi-stage multilinear polynomial
/// IOP. In each round of the protocol, the prover is allowed to send a commitment of type
/// [MultilinearPcsVerifier::Commitment] which represents a multilinear polynomials. After
/// all the rounds are complete, the verifier can check an evaluation claim for the polynomial whose
/// evaluations on the Boolean hypercube are the concatenation of all the polynomials sent.
pub trait MultilinearPcsVerifier<GC: IopCtx>: 'static + Send + Sync + Clone {
    /// The proof of a multilinear PCS evaluation.
    type Proof: 'static + Clone + Serialize + DeserializeOwned + Send + Sync;

    /// The error type of the verifier.
    type VerifierError: Error;

    fn num_expected_commitments(&self) -> usize;

    /// Verify an evaluation proof for multilinear polynomials sent.
    ///
    /// All inputs are assumed to "trusted" in the sense of Fiat-Shamir. Namely, it is assumed that
    /// the inputs have already been absorbed into the Fiat-Shamir randomness represented by the
    /// challenger.
    ///
    /// ### Arguments
    ///
    /// * `commitments` - The commitments to the multilinear polynomials sent by the prover. A
    ///   commitment is sent for each round of the protocol.
    /// * `point` - The evaluation point at which the multilinear polynomials are evaluated.
    /// * `evaluation_claim` - The evaluation claim for the multilinear polynomial.
    /// * `proof` - The proof of the evaluation claims.
    /// * `challenger` - The challenger that creates the verifier messages of the IOP.
    fn verify_trusted_evaluation(
        &self,
        commitments: &[GC::Digest],
        round_polynomial_sizes: &[usize],
        point: Point<GC::EF>,
        evaluation_claim: GC::EF,
        proof: &Self::Proof,
        challenger: &mut GC::Challenger,
    ) -> Result<(), Self::VerifierError>;

    /// Verify an evaluation proof for a multilinear polynomial.
    ///
    /// This is a variant of [MultilinearPcsVerifier::verify_trusted_evaluations] that allows the
    /// evaluation to be "untrusted" in the sense of Fiat-Shamir. Namely, the verifier will first
    /// absorb the evaluation claim into the Fiat-Shamir randomness represented by the challenger.
    fn verify_untrusted_evaluation(
        &self,
        commitments: &[GC::Digest],
        round_polynomial_sizes: &[usize],
        point: Point<GC::EF>,
        evaluation_claim: GC::EF,
        proof: &Self::Proof,
        challenger: &mut GC::Challenger,
    ) -> Result<(), Self::VerifierError> {
        // Observe the evaluation claim.
        challenger.observe_ext_element(evaluation_claim);

        self.verify_trusted_evaluation(
            commitments,
            round_polynomial_sizes,
            point,
            evaluation_claim,
            proof,
            challenger,
        )
    }

    /// The jagged verifier will assume that the underlying PCS will pad commitments to a multiple
    /// of `1<<log.stacking_height(verifier)`.
    fn log_stacking_height(verifier: &Self) -> u32;
}

/// A trait for prover data that can be converted into the original "committed-to" MLEs.
pub trait ToMle<F: Field> {
    fn interleaved_mles(&self) -> Message<Mle<F, CpuBackend>>;
}

// A prover trait for proving evaluations of a single multilinear polynomial.
pub trait MultilinearPcsProver<GC: IopCtx, Proof>: 'static + Send + Sync {
    /// The auxilary data for a prover.
    ///
    /// When committing to a batch of multilinear polynomials, it is often necessary to keep track
    /// of additional information that was produced during the commitment phase.
    type ProverData: 'static + Send + Sync + Debug + Clone + ToMle<GC::F>;

    /// The error type of the prover.
    type ProverError: Error;

    /// It is permitted to commit to multiple multilinear polynomials, whose concatenation will
    /// represent the multilinear polynomial whose evaluation is to be proved.
    fn commit_multilinear(
        &self,
        mles: Message<Mle<GC::F>>,
    ) -> Result<(GC::Digest, Self::ProverData, usize), Self::ProverError>;

    fn prove_trusted_evaluation(
        &self,
        eval_point: Point<GC::EF>,
        evaluation_claim: GC::EF,
        prover_data: Rounds<Self::ProverData>,
        challenger: &mut GC::Challenger,
    ) -> Result<Proof, Self::ProverError>;

    fn prove_untrusted_evaluation(
        &self,
        eval_point: Point<GC::EF>,
        evaluation_claim: GC::EF,
        prover_data: Rounds<Self::ProverData>,
        challenger: &mut GC::Challenger,
    ) -> Result<Proof, Self::ProverError> {
        // Observe the evaluation claim.
        challenger.observe_ext_element(evaluation_claim);

        self.prove_trusted_evaluation(eval_point, evaluation_claim, prover_data, challenger)
    }

    fn log_max_padding_amount(&self) -> u32;
}

impl<F, A: Backend> IntoIterator for Evaluations<F, A> {
    type Item = MleEval<F, A>;
    type IntoIter = <Vec<MleEval<F, A>> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.round_evaluations.into_iter()
    }
}

impl<'a, F, A: Backend> IntoIterator for &'a Evaluations<F, A> {
    type Item = &'a MleEval<F, A>;
    type IntoIter = std::slice::Iter<'a, MleEval<F, A>>;

    fn into_iter(self) -> Self::IntoIter {
        self.round_evaluations.iter()
    }
}

impl<F, A: Backend> Evaluations<F, A> {
    #[inline]
    pub fn iter(&'_ self) -> std::slice::Iter<'_, MleEval<F, A>> {
        self.round_evaluations.iter()
    }

    #[inline]
    pub const fn new(round_evaluations: Vec<MleEval<F, A>>) -> Self {
        Self { round_evaluations }
    }
}

impl<F, A: Backend> FromIterator<MleEval<F, A>> for Evaluations<F, A> {
    fn from_iter<T: IntoIterator<Item = MleEval<F, A>>>(iter: T) -> Self {
        Self { round_evaluations: iter.into_iter().collect() }
    }
}

impl<F, A: Backend> Extend<MleEval<F, A>> for Evaluations<F, A> {
    fn extend<T: IntoIterator<Item = MleEval<F, A>>>(&mut self, iter: T) {
        self.round_evaluations.extend(iter);
    }
}

impl<F, A> HasBackend for Evaluations<F, A>
where
    A: Backend,
{
    type Backend = A;

    fn backend(&self) -> &Self::Backend {
        assert!(!self.round_evaluations.is_empty(), "Evaluations must not be empty");
        self.round_evaluations.first().unwrap().backend()
    }
}

impl<F, A: Backend> Default for Evaluations<F, A> {
    fn default() -> Self {
        Self { round_evaluations: Vec::new() }
    }
}

impl<F, A: Backend> Deref for Evaluations<F, A> {
    type Target = Vec<MleEval<F, A>>;

    fn deref(&self) -> &Self::Target {
        &self.round_evaluations
    }
}

impl<F, A: Backend> DerefMut for Evaluations<F, A> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.round_evaluations
    }
}

pub trait MultilinearPcsChallenger<F: Field>: FieldChallenger<F> {
    fn sample_point<EF: ExtensionField<F>>(&mut self, num_variables: u32) -> Point<EF> {
        (0..num_variables).map(|_| self.sample_ext_element::<EF>()).collect()
    }
}

impl<F: Field, C> MultilinearPcsChallenger<F> for C where C: FieldChallenger<F> {}
