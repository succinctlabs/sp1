use std::collections::{BTreeMap, BTreeSet};

use slop_algebra::AbstractField;
use slop_alloc::{CanCopyFromRef, CpuBackend, ToHost};
use slop_challenger::{
    CanObserve, FieldChallenger, GrindingChallenger, IopCtx, VariableLengthChallenger,
};
use slop_multilinear::{Mle, MultilinearPcsChallenger, Point};

use crate::{
    air::MachineAir, prove_gkr_round, prover::Traces, Chip, ChipEvaluation, LogupGkrCpuCircuit,
    LogupGkrCpuTraceGenerator, ShardContext, GKR_GRINDING_BITS,
};

use super::{LogUpEvaluations, LogUpGkrOutput, LogupGkrProof, LogupGkrRoundProof};

/// TODO
pub struct GkrProverImpl<GC: IopCtx, SC: ShardContext<GC>> {
    /// TODO
    trace_generator: LogupGkrCpuTraceGenerator<GC::F, GC::EF, SC::Air>,
}

/// TODO
impl<GC: IopCtx, SC: ShardContext<GC>> GkrProverImpl<GC, SC> {
    /// TODO
    #[must_use]
    pub fn new(trace_generator: LogupGkrCpuTraceGenerator<GC::F, GC::EF, SC::Air>) -> Self {
        Self { trace_generator }
    }

    /// TODO
    pub fn prove_gkr_circuit(
        &self,
        numerator_value: GC::EF,
        denominator_value: GC::EF,
        eval_point: Point<GC::EF>,
        mut circuit: LogupGkrCpuCircuit<GC::F, GC::EF>,
        challenger: &mut GC::Challenger,
    ) -> (Point<GC::EF>, Vec<LogupGkrRoundProof<GC::EF>>) {
        let mut round_proofs = Vec::new();
        // Follow the GKR protocol layer by layer.
        let mut numerator_eval = numerator_value;
        let mut denominator_eval = denominator_value;
        let mut eval_point = eval_point;
        while let Some(layer) = circuit.next_layer() {
            let round_proof =
                prove_gkr_round(layer, &eval_point, numerator_eval, denominator_eval, challenger);
            // Observe the prover message.
            challenger.observe_ext_element(round_proof.numerator_0);
            challenger.observe_ext_element(round_proof.numerator_1);
            challenger.observe_ext_element(round_proof.denominator_0);
            challenger.observe_ext_element(round_proof.denominator_1);
            // Get the evaluation point for the claims of the next round.
            eval_point = round_proof.sumcheck_proof.point_and_eval.0.clone();
            // Sample the last coordinate.
            let last_coordinate = challenger.sample_ext_element::<GC::EF>();
            // Compute the evaluation of the numerator and denominator at the last coordinate.
            numerator_eval = round_proof.numerator_0
                + (round_proof.numerator_1 - round_proof.numerator_0) * last_coordinate;
            denominator_eval = round_proof.denominator_0
                + (round_proof.denominator_1 - round_proof.denominator_0) * last_coordinate;
            eval_point.add_dimension_back(last_coordinate);
            // Add the round proof to the total
            round_proofs.push(round_proof);
        }
        (eval_point, round_proofs)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prove_logup_gkr(
        &self,
        chips: &BTreeSet<Chip<GC::F, SC::Air>>,
        preprocessed_traces: &Traces<GC::F, CpuBackend>,
        traces: &Traces<GC::F, CpuBackend>,
        public_values: Vec<GC::F>,
        challenger: &mut GC::Challenger,
    ) -> LogupGkrProof<<GC::Challenger as GrindingChallenger>::Witness, GC::EF> {
        let max_interaction_arity = chips
            .iter()
            .flat_map(|c| c.sends().iter().chain(c.receives().iter()))
            .map(|i| i.values.len() + 1)
            .max()
            .unwrap();
        let beta_seed_dim = max_interaction_arity.next_power_of_two().ilog2();

        let witness = challenger.grind(GKR_GRINDING_BITS);

        // Sample the logup challenges.
        let alpha = challenger.sample_ext_element::<GC::EF>();
        let beta_seed = (0..beta_seed_dim)
            .map(|_| challenger.sample_ext_element::<GC::EF>())
            .collect::<Point<_>>();
        let _pv_challenge = challenger.sample_ext_element::<GC::EF>();

        let num_interactions =
            chips.iter().map(|chip| chip.sends().len() + chip.receives().len()).sum::<usize>();
        let num_interaction_variables = num_interactions.next_power_of_two().ilog2();

        #[cfg(sp1_debug_constraints)]
        {
            use crate::{
                air::InteractionScope, debug_interactions_with_all_chips, InteractionKind,
            };
            use slop_alloc::CanCopyIntoRef;

            let mut host_preprocessed_traces = BTreeMap::new();

            for (name, preprocessed_trace) in preprocessed_traces.iter() {
                let host_preprocessed_trace =
                    CpuBackend::copy_to_dst(&CpuBackend, preprocessed_trace).unwrap();
                host_preprocessed_traces.insert(name.clone(), host_preprocessed_trace);
            }

            let mut host_traces = BTreeMap::new();
            for (name, trace) in traces.iter() {
                let host_trace = CpuBackend::copy_to_dst(&CpuBackend, trace).unwrap();
                host_traces.insert(name.clone(), host_trace);
            }

            let host_traces = Traces { named_traces: host_traces };

            let host_preprocessed_traces = Traces { named_traces: host_preprocessed_traces };

            debug_interactions_with_all_chips::<GC::F, SC::Air>(
                &chips.iter().cloned().collect::<Vec<_>>(),
                &host_preprocessed_traces,
                &host_traces,
                public_values.clone(),
                InteractionKind::all_kinds(),
                InteractionScope::Local,
            );
        }

        // Run the GKR circuit and get the output.
        let (output, circuit) = {
            let _span = tracing::debug_span!("generate GKR circuit").entered();
            self.trace_generator.generate_gkr_circuit(
                chips,
                preprocessed_traces.clone(),
                traces.clone(),
                public_values,
                alpha,
                beta_seed,
            )
        };

        let LogUpGkrOutput { numerator, denominator } = &output;

        let host_numerator = numerator.to_host().unwrap();
        let host_denominator = denominator.to_host().unwrap();

        challenger.observe_variable_length_extension_slice(host_numerator.guts().as_slice());
        challenger.observe_variable_length_extension_slice(host_denominator.guts().as_slice());
        let output_host =
            LogUpGkrOutput { numerator: host_numerator, denominator: host_denominator };

        // TODO: instead calculate from number of interactions.
        let initial_number_of_variables = numerator.num_variables();
        assert_eq!(initial_number_of_variables, num_interaction_variables + 1);
        let first_eval_point = challenger.sample_point::<GC::EF>(initial_number_of_variables);

        // Follow the GKR protocol layer by layer.
        let first_point = numerator.backend().copy_to(&first_eval_point).unwrap();
        let first_point_eq = Mle::partial_lagrange(&first_point);
        let first_numerator_eval = numerator.eval_at_eq(&first_point_eq).to_host().unwrap()[0];
        let first_denominator_eval = denominator.eval_at_eq(&first_point_eq).to_host().unwrap()[0];

        let (eval_point, round_proofs) = {
            let _span = tracing::debug_span!("prove GKR circuit").entered();
            self.prove_gkr_circuit(
                first_numerator_eval,
                first_denominator_eval,
                first_eval_point,
                circuit,
                challenger,
            )
        };

        // Get the evaluations for each chip at the evaluation point of the last round.
        let mut chip_evaluations = BTreeMap::new();

        let trace_dimension = traces.values().next().unwrap().num_variables();
        let eval_point = eval_point.last_k(trace_dimension as usize);
        let eval_point_b = numerator.backend().copy_to(&eval_point).unwrap();
        let eval_point_eq = Mle::partial_lagrange(&eval_point_b);

        challenger.observe(GC::F::from_canonical_usize(chips.len()));
        for chip in chips.iter() {
            let name = chip.name();
            let main_trace = traces.get(name).unwrap();
            let preprocessed_trace = preprocessed_traces.get(name);

            let main_evaluation = main_trace.eval_at_eq(&eval_point, &eval_point_eq);
            let preprocessed_evaluation =
                preprocessed_trace.as_ref().map(|t| t.eval_at_eq(&eval_point, &eval_point_eq));
            let main_evaluation = main_evaluation.to_host().unwrap();
            let preprocessed_evaluation = preprocessed_evaluation.map(|e| e.to_host().unwrap());
            let openings = ChipEvaluation {
                main_trace_evaluations: main_evaluation,
                preprocessed_trace_evaluations: preprocessed_evaluation,
            };
            // Observe the openings.
            if let Some(prep_eval) = openings.preprocessed_trace_evaluations.as_ref() {
                challenger.observe_variable_length_extension_slice(prep_eval);
            }
            challenger.observe_variable_length_extension_slice(&openings.main_trace_evaluations);

            chip_evaluations.insert(name.to_string(), openings);
        }

        let logup_evaluations =
            LogUpEvaluations { point: eval_point, chip_openings: chip_evaluations };

        LogupGkrProof { circuit_output: output_host, round_proofs, logup_evaluations, witness }
    }
}
