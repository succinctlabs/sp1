use std::ops::{Add, Mul};

use serde::Serialize;
use slop_challenger::IopCtx;
use slop_commit::{Message, Rounds};

use crate::{Mle, Point};

/// Encodes a multilinear polynomial into the codeword consumed by a [`BatchPcsProver`].
///
/// A stacked-PCS prover must encode the random-linear-combination polynomial *during* proving
/// (its coefficients depend on challenges sampled mid-protocol), so the encoding step has to be
/// available separately from commitment. This trait abstracts that PCS-specific encoding so a
/// generic stacked prover can produce the right codeword (via [`BatchPcsProver::encoder`])
/// without knowing how.
///
/// # Consistency requirements (soundness-critical)
///
/// The [`BatchPcsProver::Encoder`] associated type only fixes the codeword *type*; it does **not**
/// guarantee the encoding is correct. For the mid-proof codeword to be checkable against the
/// committed oracles, the encoder a [`BatchPcsProver`] supplies must satisfy two properties that
/// the type system cannot enforce:
///
/// 1. **Same encoding as [`BatchPcsProver::commit_mles`].** It must produce codewords on the
///    *same* evaluation domain, basis, and blowup that the base PCS used to commit the oracles
///    being opened. The opening checks the encoded RLC codeword against the opened committed
///    columns, so a mismatched encoder silently breaks that check.
/// 2. **Linearity.** The verifier reconstructs the virtual oracle as a linear combination of the
///    opened committed leaves, so `encode` must be linear (`encode(Σ cᵢ·mᵢ) = Σ cᵢ·encode(mᵢ)`) for
///    the prover-side codeword to agree with it.
pub trait MleEncoder<F> {
    /// The codeword produced; what the corresponding [`BatchPcsProver::prove`] consumes.
    type Codeword;

    /// The log2 blowup factor used by [`Self::encode`]. This fixes the rate (and therefore the
    /// evaluation domain) of the codewords [`Self::encode`] produces.
    fn log_blowup(&self) -> usize;

    /// Encode a single MLE into its codeword at an arbitrary log2 blowup factor, bypassing the
    /// encoder's configured blowup.
    ///
    /// This is the general encoding primitive; [`Self::encode`] is the specialization at the
    /// encoder's configured blowup ([`Self::log_blowup`]).
    fn encode_with_log_blowup(&self, mle: Mle<F>, log_blowup: usize) -> Self::Codeword;

    /// Encode a single MLE at the encoder's configured blowup ([`Self::log_blowup`]).
    fn encode(&self, mle: Mle<F>) -> Self::Codeword {
        self.encode_with_log_blowup(mle, self.log_blowup())
    }
}

/// A way to convert leaves of one or more oracle commitments into the eval value the oracle is
/// supposed to encode.
///
/// The leaf values are grouped by commitment using the [`Rounds`] idiom: `leaf_values[j]` are the
/// values opened from commitment `j` (in commitment order). A single-commitment oracle is just the
/// special case of a one-round [`Rounds`]; a *cross-commitment* oracle reads across several rounds.
pub trait OracleEval<In, Out>: Send {
    fn evaluate_oracle(&self, leaf_values: Rounds<&[In]>, index: usize) -> Out;
}

impl<In, Out, Eval> OracleEval<In, Out> for Eval
where
    Eval: Send + Fn(Rounds<&[In]>, usize) -> Out,
{
    fn evaluate_oracle(&self, leaf_values: Rounds<&[In]>, index: usize) -> Out {
        self(leaf_values, index)
    }
}

/// An Oracle Eval that's known to be linear.
#[derive(Clone, Debug, Serialize)]
pub struct LinearOracleEval<F> {
    pub coeffs: Vec<F>,
}

impl<In, Out, F: Copy + Send + Sync> OracleEval<In, Out> for LinearOracleEval<F>
where
    In: Clone + Mul<F, Output = Out>,
    Out: Add<Out, Output = Out>,
{
    fn evaluate_oracle(&self, leaf_values: Rounds<&[In]>, _index: usize) -> Out {
        // The coefficients span every round's leaves concatenated in commitment order, so we flatten
        // across rounds before zipping. A one-round input reproduces the single-commitment behavior.
        self.coeffs
            .iter()
            .zip(leaf_values.iter().flat_map(|round| round.iter()))
            .map(|(c, v)| v.clone() * *c)
            .reduce(|acc, x| acc + x)
            .expect("LinearOracleEval requires at least one coefficient")
    }
}

/// A verifier for a PCS that acts on MLEs committed virtually: the MLE is a bunch of literally
/// committed MLEs that have been batched in some sense.
pub trait BatchPcsVerifier<GC: IopCtx> {
    type Proof;
    /// The commitment to a single committed oracle — the same unit as
    /// [`BatchPcsProver::Commitment`]. A single [`Self::verify`] call opens a *slice* of these
    /// (one per oracle batched into the proof).
    type Commitment: Into<GC::Digest>;
    type VerifierError: std::error::Error + 'static;

    /// The number of query openings contained in a proof (the query count required for a sound proximity-test).
    fn num_queries(&self) -> usize;

    /// The fixed number of variables of the MLEs this verifier's commitments are over (the log of
    /// the committed message length). Every commitment opened by [`Self::verify`] is over MLEs of
    /// exactly this many variables, so the `reduced_point` must have this dimension.
    fn num_encoding_variables(&self) -> u32;

    /// The log2 blowup factor of the committed Reed–Solomon codewords.
    ///
    /// Together with [`Self::num_encoding_variables`] this fixes the evaluation domain (of size
    /// `2^(num_encoding_variables + log_blowup)`) over which query openings are taken. A caller
    /// needs it to map a query index to its domain point (e.g. for the ZK padding correction in
    /// Veil).
    fn log_blowup(&self) -> usize;

    /// Verify a batched evaluation claim.
    ///
    /// - `commits` are the commitments to the oracles being opened, one per batched oracle (in
    ///   commitment order).
    /// - `point`/`eval` are the evaluation point and the claimed batched evaluation.
    /// - `oracle_evaluator` turns the raw committed leaf values opened at each query — grouped by
    ///   commitment as [`Rounds`] (one round per batched oracle) — into the value of the *virtual*
    ///   oracle the proof is actually about (see [`OracleEval`]).
    /// - `challenger` carries the Fiat–Shamir state; it must match the prover's.
    fn verify(
        &self,
        commits: &[Self::Commitment],
        reduced_point: &Point<GC::EF>,
        reduced_eval: GC::EF,
        oracle_evaluator: impl OracleEval<GC::F, GC::EF>,
        proof: &Self::Proof,
        challenger: &mut GC::Challenger,
    ) -> Result<(), Self::VerifierError>;
}

/// A prover for a PCS that acts on MLEs committed virtually: the MLE is a bunch of literally
/// committed MLEs that have been batched in some sense.
pub trait BatchPcsProver<GC: IopCtx> {
    type Proof;
    type ProverError: std::error::Error + 'static;
    /// The commitment to a batch of committed oracles. Convertible into the context's canonical
    /// digest type, since it is observed by the Fiat–Shamir challenger as a digest.
    type Commitment: Into<GC::Digest>;
    /// The encoder producing the codewords [`Self::prove`] consumes. The implementor must
    /// guarantee it encodes exactly the way [`Self::commit_mles`] encodes the committed oracles —
    /// see the consistency requirements on [`MleEncoder`].
    type Encoder: MleEncoder<GC::F>;
    /// Per-commitment prover data captured by [`Self::commit_mles`], used to open the committed
    /// columns.
    type ProverData;

    /// The number of query openings a proof will contain (the query count required for a sound
    /// proximity-test). Matches the corresponding [`BatchPcsVerifier::num_queries`].
    fn num_queries(&self) -> usize;

    /// The fixed number of variables of the MLEs this prover commits to (the log of the committed
    /// message length). Matches the corresponding [`BatchPcsVerifier::num_encoding_variables`].
    fn num_encoding_variables(&self) -> u32;

    /// The encoder for polynomials built mid-proof (e.g. a stacked prover's RLC polynomial), whose
    /// codewords [`Self::prove`] checks against the committed oracles.
    fn encoder(&self) -> &Self::Encoder;

    /// Commit to a batch of multilinears at an arbitrary log2 blowup factor, returning the
    /// commitment and the prover data needed to later open them.
    ///
    /// This is the general commit primitive; [`Self::commit_mles`] is the specialization at the
    /// encoder's configured blowup ([`MleEncoder::log_blowup`]). Committing at a *reduced* blowup is
    /// how a ZK layer keeps the committed tensor the same size after appending hiding rows (the
    /// caller is responsible for any row padding the reduced rate assumes).
    fn commit_mles_with_log_blowup(
        &self,
        mles: Message<Mle<GC::F>>,
        log_blowup: usize,
    ) -> Result<(Self::Commitment, Self::ProverData), Self::ProverError>;

    /// Commit to a batch of multilinears at the encoder's configured blowup
    /// ([`MleEncoder::log_blowup`]), returning the commitment and the prover data needed to later
    /// open them.
    fn commit_mles(
        &self,
        mles: Message<Mle<GC::F>>,
    ) -> Result<(Self::Commitment, Self::ProverData), Self::ProverError> {
        self.commit_mles_with_log_blowup(mles, self.encoder().log_blowup())
    }

    /// Prove a batched evaluation claim.
    ///
    /// The caller is responsible for having batched the committed oracles into
    /// `batched_polynomial`/`batched_codeword` and computing the matching `eval`; this only runs
    /// the core opening protocol. `prover_data` is the per-commitment data captured at commit time
    /// (one entry per committed oracle) and `challenger` carries the Fiat–Shamir state.
    fn prove(
        &self,
        reduced_point: &Point<GC::EF>,
        reduced_eval: GC::EF,
        batched_polynomial: Mle<GC::EF>,
        batched_codeword: <Self::Encoder as MleEncoder<GC::F>>::Codeword,
        prover_data: Rounds<Self::ProverData>,
        challenger: &mut GC::Challenger,
    ) -> Result<Self::Proof, Self::ProverError>;
}
