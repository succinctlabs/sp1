use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use slop_algebra::Field;
use slop_alloc::{Backend, CpuBackend};
use slop_multilinear::{Mle, MleEval, Point};
use slop_sumcheck::PartialSumcheckProof;

/// The output of the log-up GKR circuit.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(bound(serialize = "Mle<EF, B>: Serialize", deserialize = "Mle<EF, B>: Deserialize<'de>"))]
pub struct LogUpGkrOutput<EF, B: Backend = CpuBackend> {
    /// Numerator
    pub numerator: Mle<EF, B>,
    /// Denominator
    pub denominator: Mle<EF, B>,
}

/// The cumulative sum of a single global-scope interaction, exposed in the clear as a raw
/// `(numerator, denominator)` fraction (`numerator / denominator` is the interaction's total over
/// all its trace rows, fingerprinted with the global challenge pair).
///
/// These are extracted at the "one entry per interaction" layer of the GKR circuit — where the
/// global-scope interactions occupy the block `[2^k_local, 2^k_local + num_global)` of the grouped
/// interaction order, above the local block and its padding — and sent to the verifier so the
/// per-shard global sums can be checked to cancel across shards. They are bound to the committed
/// traces by the GKR itself: the transition fold splices them into the circuit's evaluation claim,
/// which is checked all the way down to the leaves.
pub type GlobalInteractionOutput<EF> = (EF, EF);

/// The cumulative sum (`Σ numerator_i / denominator_i`) of a slice of exposed global-interaction
/// outputs.
#[must_use]
pub fn global_output_sum<EF: Field>(outputs: &[GlobalInteractionOutput<EF>]) -> EF {
    outputs.iter().map(|(numerator, denominator)| *numerator / *denominator).sum()
}

/// The proof for a single round of the log-up GKR circuit.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogupGkrRoundProof<EF> {
    /// The numerator of the numerator with last coordinate being 0.
    pub numerator_0: EF,
    /// The numerator of the numerator with last coordinate being 1.
    pub numerator_1: EF,
    /// The denominator of the denominator with last coordinate being 0.
    pub denominator_0: EF,
    /// The denominator of the denominator with last coordinate being 1.
    pub denominator_1: EF,
    /// The sumcheck proof for the round.
    pub sumcheck_proof: PartialSumcheckProof<EF>,
}

/// The proof for the log-up GKR circuit.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogupGkrProof<F, EF> {
    /// The output of the circuit.
    pub circuit_output: LogUpGkrOutput<EF>,
    /// The per-interaction cumulative sums of the global-scope interactions, exposed in the clear
    /// (one raw `(numerator, denominator)` per global interaction, in the circuit's grouped
    /// interaction order). Empty on machines without a global round. See
    /// [`GlobalInteractionOutput`].
    pub global_interaction_outputs: Vec<GlobalInteractionOutput<EF>>,
    /// The proof for each round.
    pub round_proofs: Vec<LogupGkrRoundProof<EF>>,
    /// The evaluations for each chip.
    pub logup_evaluations: LogUpEvaluations<EF>,
    /// The grinding witness.
    pub witness: F,
}

/// The evaluations for a chip
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChipEvaluation<EF> {
    /// The evaluations of the main trace.
    pub main_trace_evaluations: MleEval<EF>,
    /// The evaluations of the preprocessed trace.
    pub preprocessed_trace_evaluations: MleEval<EF>,
    /// The evaluations of the global trace.
    pub global_trace_evaluations: MleEval<EF>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
/// The data passed from the GKR prover to the zerocheck prover.
pub struct LogUpEvaluations<EF> {
    /// The point at which the evaluations are made.
    pub point: Point<EF>,
    /// The evaluations for each chip.
    pub chip_openings: BTreeMap<String, ChipEvaluation<EF>>,
}
