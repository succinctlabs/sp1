use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
    ops::Range,
    sync::Arc,
};

use slop_algebra::{ExtensionField, Field};
use slop_alloc::CpuBackend;
use slop_challenger::FieldChallenger;
use slop_multilinear::{Mle, PaddedMle, Point};
use slop_sumcheck::reduce_sumcheck_to_evaluation;

use crate::{
    air::{InteractionScope, MachineAir},
    prover::Traces,
    Chip, Interaction, LogupRoundPolynomial, PolynomialLayer,
};

use super::{GlobalInteractionOutput, LogUpGkrOutput};

/// The grouped interaction-index ranges of a chip: the range of its local-scope interactions in
/// the local block `[0, num_local)`, and the range of its global-scope interactions in the global
/// block starting at `2^k_local`.
pub type ChipInteractionRanges = (Range<usize>, Range<usize>);

/// A chip's GKR interactions — the interaction list in grouped within-chip order (local-scope
/// first, then global-scope, each in sends-then-receives order) with the send flag — together
/// with the chip's grouped index ranges.
pub(crate) type ChipInteractions<'a, F> = (Vec<(&'a Interaction<F>, bool)>, ChipInteractionRanges);

/// A trace generator for the GKR circuit.
pub struct LogupGkrCpuTraceGenerator<F, EF, A>(PhantomData<(F, EF, A)>);

impl<F, EF, A> Default for LogupGkrCpuTraceGenerator<F, EF, A> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

/// A trace generator for the GKR circuit.
pub struct LogupGkrCpuCircuit<F: Field, EF> {
    layers: Vec<GkrCircuitLayer<F, EF>>,
    /// The number of local-only interaction tree rounds proved before the transition fold (these
    /// layers are popped first). Zero on machines without a global round.
    pub(crate) num_local_layers: usize,
    /// The transition-fold data, present iff the machine has a global round.
    pub(crate) transition: Option<TransitionData<EF>>,
}

/// The data required to splice the exposed global-scope interaction outputs into the GKR
/// evaluation claim at the "one entry per interaction" layer — the boundary between the
/// local-only interaction tree (above) and the full circuit (below).
pub(crate) struct TransitionData<EF> {
    /// The interaction-variable count of the local-only tree.
    pub(crate) k_local: usize,
    /// The interaction-variable count of the full circuit.
    pub(crate) k_full: usize,
    /// The exposed global-scope interaction outputs, in grouped order (grouped index
    /// `2^k_local + i` is the `i`-th global interaction).
    pub(crate) global_outputs: Vec<GlobalInteractionOutput<EF>>,
}

/// A layer of the GKR circuit.
pub enum GkrCircuitLayer<F: Field, EF> {
    /// An intermediate layer of the GKR circuit.
    Layer(LogUpGkrCpuLayer<EF, EF>),
    /// The first layer of the GKR circuit.
    FirstLayer(LogUpGkrCpuLayer<F, EF>),
    /// A layer combining the interaction dimension (the row variables are already consumed).
    ///
    /// These layers sit above the row layers in the GKR tree: the first of them combines the
    /// interleaved base pairs into the "one entry per interaction" layer, and the ones above it
    /// reduce the proved interaction tree down to a single pair of fractions.
    InteractionLayer(InteractionLayer<EF, EF>),
}

/// A layer of the GKR circuit.
pub struct LogUpGkrCpuLayer<F, EF> {
    /// The numerators of the layer (`PaddedMle<F>` per table with dimensions `num_row_variables` x
    /// `num_interaction_variables`)
    pub numerator_0: Vec<PaddedMle<F>>,
    /// The denominators of the layer (`PaddedMle<EF>` per table with dimensions
    /// `num_row_variables` x `num_interaction_variables`)
    pub denominator_0: Vec<PaddedMle<EF>>,
    /// The numerators of the layer (`PaddedMle<F>` per table with dimensions `num_row_variables` x
    /// `num_interaction_variables`)
    pub numerator_1: Vec<PaddedMle<F>>,
    /// The denominators of the layer (`PaddedMle<EF>` per table with dimensions
    /// `num_row_variables` x `num_interaction_variables`)
    pub denominator_1: Vec<PaddedMle<EF>>,
    /// The grouped interaction-index ranges of each table, parallel to the `PaddedMle` vectors:
    /// each table's columns are its local-scope interactions (mapped into the local block)
    /// followed by its global-scope interactions (mapped into the global block at `2^k_local`).
    pub interaction_ranges: Vec<ChipInteractionRanges>,
    /// The number of row variables (log height of each mle)
    pub num_row_variables: usize,
    /// The number of interaction variables (log width of each mle)
    pub num_interaction_variables: usize,
}

/// An interaction layer of the GKR circuit (`num_row_variables` == 1).
pub struct InteractionLayer<F, EF> {
    /// The numerators of the layer (`PaddedMle<F>` per table with dimensions
    /// `num_interaction_variables` x 1)
    pub numerator_0: Arc<Mle<F>>,
    /// The denominators of the layer (`PaddedMle<EF>` per table with dimensions
    /// `num_interaction_variables` x 1)
    pub denominator_0: Arc<Mle<EF>>,
    /// The numerators of the layer (`PaddedMle<F>` per table with dimensions
    /// `num_interaction_variables` x 1)
    pub numerator_1: Arc<Mle<F>>,
    /// The denominators of the layer (`PaddedMle<EF>` per table with dimensions
    /// `num_interaction_variables` x 1)
    pub denominator_1: Arc<Mle<EF>>,
}

impl<F: Field, EF: ExtensionField<F>, A: MachineAir<F>> LogupGkrCpuTraceGenerator<F, EF, A> {
    #[allow(unused_variables)]
    #[allow(clippy::needless_pass_by_value)]
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_lines)]
    pub(crate) fn generate_gkr_circuit(
        &self,
        chips: &BTreeSet<Chip<F, A>>,
        preprocessed_traces: Traces<F, CpuBackend>,
        global_traces: Traces<F, CpuBackend>,
        traces: Traces<F, CpuBackend>,
        public_values: Vec<F>,
        local_challenges: (EF, Point<EF>),
        global_challenges: Option<(EF, Point<EF>)>,
    ) -> (LogUpGkrOutput<EF>, LogupGkrCpuCircuit<F, EF>, Vec<GlobalInteractionOutput<EF>>) {
        let has_global_round = global_challenges.is_some();

        // Partition each chip's interactions by scope (a stable partition: sends then receives
        // within each scope), skipping interaction-free chips.
        let partitioned = chips
            .iter()
            .filter(|chip| chip.num_interactions() > 0)
            .map(|chip| {
                let (locals, globals): (Vec<_>, Vec<_>) = chip
                    .sends()
                    .iter()
                    .map(|int| (int, true))
                    .chain(chip.receives().iter().map(|int| (int, false)))
                    .partition(|(interaction, _)| interaction.scope == InteractionScope::Local);
                (chip.name().to_string(), locals, globals)
            })
            .collect::<Vec<_>>();

        // The grouped interaction-dimension shape, mirroring the verifier's derivation: the
        // local-scope interactions form the low block `[0, num_local)`, the slots
        // `[num_local, 2^k_local)` are padding, and the global-scope interactions form the block
        // starting at `2^k_local` (separated from the local tree's padding slots, which the
        // transition fold pins to the padding values), followed by padding up to `2^k_full`.
        let num_local = partitioned.iter().map(|(_, locals, _)| locals.len()).sum::<usize>();
        let num_global = partitioned.iter().map(|(_, _, globals)| globals.len()).sum::<usize>();
        let k_local = num_local.next_power_of_two().ilog2().max(1) as usize;
        let k_full = if num_global > 0 {
            ((1usize << k_local) + num_global).next_power_of_two().ilog2() as usize
        } else {
            k_local
        };
        let global_block_start = 1usize << k_local;

        // Each chip's interactions in grouped within-chip order (locals then globals), with the
        // chip's grouped index ranges.
        let mut local_offset = 0;
        let mut global_offset = 0;
        let interactions = partitioned
            .into_iter()
            .map(|(name, mut interactions, globals)| {
                let local_range = local_offset..local_offset + interactions.len();
                local_offset = local_range.end;
                let global_range = global_block_start + global_offset
                    ..global_block_start + global_offset + globals.len();
                global_offset = global_range.end - global_block_start;
                interactions.extend(globals);
                (name, (interactions, (local_range, global_range)))
            })
            .collect::<BTreeMap<_, _>>();

        let first_layer = self.generate_first_layer(
            &interactions,
            &traces,
            &global_traces,
            &preprocessed_traces,
            local_challenges,
            global_challenges,
            k_full,
        );
        let num_row_variables = first_layer.num_row_variables;
        let mut layers = Vec::new();
        layers.push(GkrCircuitLayer::FirstLayer(first_layer));

        for _ in 0..num_row_variables - 1 {
            let next_layer = match layers.last().unwrap() {
                GkrCircuitLayer::Layer(layer) => self.layer_transition(layer),
                GkrCircuitLayer::FirstLayer(layer) => self.layer_transition(layer),
                GkrCircuitLayer::InteractionLayer(_) => unreachable!(),
            };
            layers.push(GkrCircuitLayer::Layer(next_layer));
        }

        let last_layer = layers.last().unwrap();
        let GkrCircuitLayer::Layer(last_layer) = last_layer else { unreachable!() };
        assert_eq!(last_layer.num_row_variables, 1);

        // The row tree produces a base of `2^(k_full + 1)` fractions in grouped order (one pair
        // per interaction, with the last row variable interleaved in). The first interaction
        // level (`il_0`) combines the interleaved pairs into the "one entry per interaction"
        // layer `o_full`.
        let base = self.extract_outputs(last_layer);
        let mut o_full_numerator = base.numerator.guts().as_slice().to_vec();
        let mut o_full_denominator = base.denominator.guts().as_slice().to_vec();
        let il_0 = combine_interaction_layer(&mut o_full_numerator, &mut o_full_denominator);

        if !has_global_round {
            // No global round: combine the whole interaction dimension down to a single pair of
            // fractions. Layers are popped from the back, so the interaction layers are proved
            // first (reducing the output down toward the base), followed by the row layers.
            layers.push(GkrCircuitLayer::InteractionLayer(il_0));
            while o_full_numerator.len() > 2 {
                layers.push(GkrCircuitLayer::InteractionLayer(combine_interaction_layer(
                    &mut o_full_numerator,
                    &mut o_full_denominator,
                )));
            }
            let output = LogUpGkrOutput {
                numerator: Mle::from(o_full_numerator),
                denominator: Mle::from(o_full_denominator),
            };
            let circuit = LogupGkrCpuCircuit { layers, num_local_layers: 0, transition: None };
            return (output, circuit, Vec::new());
        }

        // A global round is present: extract the global interactions' totals (the block starting
        // at `2^k_local`) to send in the clear, and prove the interaction tree over just the
        // local block, padded up to `2^k_local`. The global block is spliced back in by the
        // transition fold when the local tree's claim reaches `il_0`.
        let global_outputs = (0..num_global)
            .map(|i| {
                let index = global_block_start + i;
                (o_full_numerator[index], o_full_denominator[index])
            })
            .collect::<Vec<_>>();

        let mut tree_numerator = vec![EF::zero(); 1 << k_local];
        let mut tree_denominator = vec![EF::one(); 1 << k_local];
        tree_numerator[..num_local].copy_from_slice(&o_full_numerator[..num_local]);
        tree_denominator[..num_local].copy_from_slice(&o_full_denominator[..num_local]);

        layers.push(GkrCircuitLayer::InteractionLayer(il_0));
        let mut num_local_layers = 0;
        while tree_numerator.len() > 2 {
            layers.push(GkrCircuitLayer::InteractionLayer(combine_interaction_layer(
                &mut tree_numerator,
                &mut tree_denominator,
            )));
            num_local_layers += 1;
        }
        let output = LogUpGkrOutput {
            numerator: Mle::from(tree_numerator),
            denominator: Mle::from(tree_denominator),
        };
        let transition = TransitionData { k_local, k_full, global_outputs: global_outputs.clone() };
        let circuit = LogupGkrCpuCircuit { layers, num_local_layers, transition: Some(transition) };

        (output, circuit, global_outputs)
    }
}

/// Combine one interaction-dimension level: fold the interleaved pairs `(2i, 2i + 1)` of
/// `numerator`/`denominator` (each of length `2n`) into their `n` fraction sums in place
/// (truncating to length `n`), returning the recorded `InteractionLayer` of the pre-combination
/// children.
pub(crate) fn combine_interaction_layer<EF: Field>(
    numerator: &mut Vec<EF>,
    denominator: &mut Vec<EF>,
) -> InteractionLayer<EF, EF> {
    let half = numerator.len() / 2;
    let mut numerator_0 = Vec::with_capacity(half);
    let mut numerator_1 = Vec::with_capacity(half);
    let mut denominator_0 = Vec::with_capacity(half);
    let mut denominator_1 = Vec::with_capacity(half);
    let mut next_numerator = Vec::with_capacity(half);
    let mut next_denominator = Vec::with_capacity(half);
    for i in 0..half {
        // The last variable is the low bit, matching `extract_outputs`' interleaving and the
        // verifier's `add_dimension_back` convention: index `2 * i` is the child with last
        // variable `0`, `2 * i + 1` is the child with last variable `1`.
        let (n0, n1) = (numerator[2 * i], numerator[2 * i + 1]);
        let (d0, d1) = (denominator[2 * i], denominator[2 * i + 1]);
        numerator_0.push(n0);
        numerator_1.push(n1);
        denominator_0.push(d0);
        denominator_1.push(d1);
        // Fraction addition of the two children.
        next_numerator.push(n0 * d1 + n1 * d0);
        next_denominator.push(d0 * d1);
    }
    *numerator = next_numerator;
    *denominator = next_denominator;
    InteractionLayer {
        numerator_0: Arc::new(Mle::from(numerator_0)),
        numerator_1: Arc::new(Mle::from(numerator_1)),
        denominator_0: Arc::new(Mle::from(denominator_0)),
        denominator_1: Arc::new(Mle::from(denominator_1)),
    }
}

impl<F: Field, EF: ExtensionField<F>> Iterator for LogupGkrCpuCircuit<F, EF> {
    type Item = GkrCircuitLayer<F, EF>;

    fn next(&mut self) -> Option<Self::Item> {
        self.layers.pop()
    }
}

/// Basic information about the GKR circuit.
impl<F: Field, EF: ExtensionField<F>> LogupGkrCpuCircuit<F, EF> {
    pub(crate) fn next_layer(&mut self) -> Option<GkrCircuitLayer<F, EF>> {
        self.layers.pop()
    }
}

pub(crate) fn prove_gkr_round<F: Field, EF: ExtensionField<F>, Challenger: FieldChallenger<F>>(
    circuit: GkrCircuitLayer<F, EF>,
    eval_point: &slop_multilinear::Point<EF>,
    numerator_eval: EF,
    denominator_eval: EF,
    challenger: &mut Challenger,
) -> super::LogupGkrRoundProof<EF> {
    let lambda = challenger.sample_ext_element::<EF>();

    let (numerator_0, denominator_0, numerator_1, denominator_1, sumcheck_proof) = match circuit {
        GkrCircuitLayer::Layer(layer) => {
            let (interaction_point, row_point) =
                eval_point.split_at(layer.num_interaction_variables);
            let eq_interaction = Mle::partial_lagrange(&interaction_point);
            let eq_row = Mle::partial_lagrange(&row_point);
            let sumcheck_poly = LogupRoundPolynomial {
                layer: PolynomialLayer::CircuitLayer(layer),
                eq_row: Arc::new(eq_row),
                eq_interaction: Arc::new(eq_interaction),
                lambda,
                eq_adjustment: EF::one(),
                padding_adjustment: EF::one(),
                point: eval_point.clone(),
            };
            let claim = numerator_eval * lambda + denominator_eval;

            let (sumcheck_proof, mut openings) = reduce_sumcheck_to_evaluation(
                vec![sumcheck_poly],
                challenger,
                vec![claim],
                1,
                lambda,
            );

            let openings = openings.pop().unwrap();
            let [numerator_0, denominator_0, numerator_1, denominator_1] =
                openings.try_into().unwrap();
            (numerator_0, denominator_0, numerator_1, denominator_1, sumcheck_proof)
        }
        GkrCircuitLayer::FirstLayer(layer) => {
            let (interaction_point, row_point) =
                eval_point.split_at(layer.num_interaction_variables);
            let eq_interaction = Mle::partial_lagrange(&interaction_point);
            let eq_row = Mle::partial_lagrange(&row_point);
            let sumcheck_poly = LogupRoundPolynomial {
                layer: PolynomialLayer::CircuitLayer(layer),
                eq_row: Arc::new(eq_row),
                eq_interaction: Arc::new(eq_interaction),
                lambda,
                eq_adjustment: EF::one(),
                padding_adjustment: EF::one(),
                point: eval_point.clone(),
            };
            let claim = numerator_eval * lambda + denominator_eval;
            let (sumcheck_proof, mut openings) = reduce_sumcheck_to_evaluation(
                vec![sumcheck_poly],
                challenger,
                vec![claim],
                1,
                lambda,
            );
            let openings = openings.pop().unwrap();
            let [numerator_0, denominator_0, numerator_1, denominator_1] =
                openings.try_into().unwrap();
            (numerator_0, denominator_0, numerator_1, denominator_1, sumcheck_proof)
        }
        GkrCircuitLayer::InteractionLayer(layer) => {
            // The whole eval point is over the interaction dimension; there is no row dimension.
            let eq_interaction = Mle::partial_lagrange(eval_point);
            let eq_row = Mle::from(vec![EF::one()]);
            let sumcheck_poly = LogupRoundPolynomial {
                layer: PolynomialLayer::InteractionLayer(layer),
                eq_row: Arc::new(eq_row),
                eq_interaction: Arc::new(eq_interaction),
                lambda,
                eq_adjustment: EF::one(),
                padding_adjustment: EF::one(),
                point: eval_point.clone(),
            };
            let claim = numerator_eval * lambda + denominator_eval;
            let (sumcheck_proof, mut openings) = reduce_sumcheck_to_evaluation(
                vec![sumcheck_poly],
                challenger,
                vec![claim],
                1,
                lambda,
            );
            let openings = openings.pop().unwrap();
            let [numerator_0, denominator_0, numerator_1, denominator_1] =
                openings.try_into().unwrap();
            (numerator_0, denominator_0, numerator_1, denominator_1, sumcheck_proof)
        }
    };

    super::LogupGkrRoundProof {
        numerator_0,
        numerator_1,
        denominator_0,
        denominator_1,
        sumcheck_proof,
    }
}
