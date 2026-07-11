use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
    sync::Arc,
};

use slop_algebra::{ExtensionField, Field};
use slop_alloc::CpuBackend;
use slop_challenger::FieldChallenger;
use slop_multilinear::{Mle, PaddedMle, Point};
use slop_sumcheck::reduce_sumcheck_to_evaluation;

use crate::{air::MachineAir, prover::Traces, Chip, LogupRoundPolynomial, PolynomialLayer};

use super::LogUpGkrOutput;

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
}

/// A layer of the GKR circuit.
pub enum GkrCircuitLayer<F: Field, EF> {
    /// An intermediate layer of the GKR circuit.
    Layer(LogUpGkrCpuLayer<EF, EF>),
    /// The first layer of the GKR circuit.
    FirstLayer(LogUpGkrCpuLayer<F, EF>),
    /// A layer combining the interaction dimension (the row variables are already consumed).
    ///
    /// These layers sit above the row layers in the GKR tree and reduce the `2^(k+1)` per-
    /// interaction fractions produced by the row tree down to a single pair of fractions.
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
    pub(crate) fn generate_gkr_circuit(
        &self,
        chips: &BTreeSet<Chip<F, A>>,
        preprocessed_traces: Traces<F, CpuBackend>,
        traces: Traces<F, CpuBackend>,
        public_values: Vec<F>,
        alpha: EF,
        beta_seed: Point<EF>,
    ) -> (LogUpGkrOutput<EF>, LogupGkrCpuCircuit<F, EF>) {
        let interactions = chips
            .iter()
            .map(|chip| {
                let interactions = chip
                    .sends()
                    .iter()
                    .map(|int| (int, true))
                    .chain(chip.receives().iter().map(|int| (int, false)))
                    .collect::<Vec<_>>();
                (chip.name().to_string(), interactions)
            })
            .collect::<BTreeMap<_, _>>();

        let first_layer = self.generate_first_layer(
            &interactions,
            &traces,
            &preprocessed_traces,
            alpha,
            beta_seed,
        );
        let num_row_variables = first_layer.num_row_variables;
        // println!("num_row_variables: {:?}", num_row_variables);
        let num_interaction_variables = first_layer.num_interaction_variables;
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
        let last_layer = match last_layer {
            GkrCircuitLayer::Layer(layer) => layer,
            GkrCircuitLayer::FirstLayer(_) | GkrCircuitLayer::InteractionLayer(_) => unreachable!(),
        };
        assert_eq!(last_layer.num_row_variables, 1);

        // The row tree produces a base of `2^(num_interaction_variables + 1)` fractions (one per
        // interaction, with the last row variable interleaved in). Combine the interaction
        // dimension all the way down to a single pair of fractions, recording an
        // `InteractionLayer` for every combination round so the sumchecks can be proved later.
        let base = self.extract_outputs(last_layer);
        let mut cur_numerator = base.numerator.guts().as_slice().to_vec();
        let mut cur_denominator = base.denominator.guts().as_slice().to_vec();

        let mut interaction_layers = Vec::with_capacity(num_interaction_variables);
        for _ in 0..num_interaction_variables {
            let half = cur_numerator.len() / 2;
            let mut numerator_0 = Vec::with_capacity(half);
            let mut numerator_1 = Vec::with_capacity(half);
            let mut denominator_0 = Vec::with_capacity(half);
            let mut denominator_1 = Vec::with_capacity(half);
            let mut next_numerator = Vec::with_capacity(half);
            let mut next_denominator = Vec::with_capacity(half);
            for i in 0..half {
                // The last variable is the low bit, matching `extract_outputs`' interleaving and
                // the verifier's `add_dimension_back` convention: index `2 * i` is the child with
                // last variable `0`, `2 * i + 1` is the child with last variable `1`.
                let (n0, n1) = (cur_numerator[2 * i], cur_numerator[2 * i + 1]);
                let (d0, d1) = (cur_denominator[2 * i], cur_denominator[2 * i + 1]);
                numerator_0.push(n0);
                numerator_1.push(n1);
                denominator_0.push(d0);
                denominator_1.push(d1);
                // Fraction addition of the two children.
                next_numerator.push(n0 * d1 + n1 * d0);
                next_denominator.push(d0 * d1);
            }
            interaction_layers.push(GkrCircuitLayer::InteractionLayer(InteractionLayer {
                numerator_0: Arc::new(Mle::from(numerator_0)),
                numerator_1: Arc::new(Mle::from(numerator_1)),
                denominator_0: Arc::new(Mle::from(denominator_0)),
                denominator_1: Arc::new(Mle::from(denominator_1)),
            }));
            cur_numerator = next_numerator;
            cur_denominator = next_denominator;
        }

        // The output is the top `level-1` layer: a single pair of fractions (dimension 2). The
        // verifier combines these two fractions into the final numerator/denominator and performs
        // a single division to check the cumulative sum.
        let output = LogUpGkrOutput {
            numerator: Mle::from(cur_numerator),
            denominator: Mle::from(cur_denominator),
        };

        // Append the interaction layers after the row layers. Layers are popped from the back, so
        // the interaction layers are proved first (reducing the output down toward the base),
        // followed by the row layers.
        layers.extend(interaction_layers);
        let circuit = LogupGkrCpuCircuit { layers };

        (output, circuit)
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
