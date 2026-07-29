use std::collections::BTreeSet;

use slop_air::BaseAir;
use slop_algebra::{ExtensionField, Field};
use slop_multilinear::Point;
use sp1_hypercube::{
    air::{InteractionScope, MachineAir},
    Chip, ChipEvaluation, LogUpEvaluations, LogUpGkrOutput, LogupGkrProof, LogupGkrRoundProof,
};

use super::sumcheck::dummy_sumcheck_proof;

pub fn dummy_gkr_proof<F: Field, EF: ExtensionField<F>, A: MachineAir<F>>(
    shard_chips: &BTreeSet<Chip<F, A>>,
    log_max_row_height: usize,
    has_global_round: bool,
) -> LogupGkrProof<F, EF> {
    // The grouped interaction-dimension shape, mirroring the verifier's derivation.
    let interaction_scopes = shard_chips
        .iter()
        .flat_map(|chip| chip.sends().iter().chain(chip.receives().iter()))
        .map(|interaction| interaction.scope)
        .collect::<Vec<_>>();
    let num_local =
        interaction_scopes.iter().filter(|scope| **scope == InteractionScope::Local).count();
    let num_global = interaction_scopes.len() - num_local;
    let k_local = num_local.next_power_of_two().ilog2().max(1) as usize;
    let k_full = if num_global > 0 {
        ((1usize << k_local) + num_global).next_power_of_two().ilog2() as usize
    } else {
        k_local
    };
    let num_interaction_rounds = if has_global_round { k_local } else { k_full };

    // The circuit output is the top `level-1` layer: a single pair of fractions.
    let circuit_output = LogUpGkrOutput {
        numerator: vec![EF::zero(); 2].into(),
        denominator: vec![EF::zero(); 2].into(),
    };

    let global_interaction_outputs = vec![(EF::zero(), EF::zero()); num_global];

    // The GKR tree runs the interaction rounds (the local-only tree and the round consuming the
    // "one entry per interaction" layer on a global round, else the full tree) followed by
    // `log_max_row_height - 1` row rounds; the transition fold jumps the point dimension from
    // `k_local` to `k_full` right before round `num_interaction_rounds - 1`.
    let num_rounds = num_interaction_rounds + log_max_row_height - 1;
    let round_proofs = (0..num_rounds)
        .map(|i| {
            let num_variables = if i < num_interaction_rounds - 1 {
                i + 1
            } else {
                k_full + i - (num_interaction_rounds - 1)
            };
            LogupGkrRoundProof {
                numerator_0: EF::zero(),
                numerator_1: EF::zero(),
                denominator_0: EF::zero(),
                denominator_1: EF::zero(),
                sumcheck_proof: dummy_sumcheck_proof::<EF>(num_variables, 3),
            }
        })
        .collect();

    let logup_evaluations = LogUpEvaluations {
        point: Point::from_usize(0, log_max_row_height),
        chip_openings: shard_chips
            .iter()
            .map(|chip| {
                (
                    chip.air.name().to_string(),
                    ChipEvaluation {
                        main_trace_evaluations: vec![EF::zero(); chip.width()].into(),
                        preprocessed_trace_evaluations: vec![EF::zero(); chip.preprocessed_width()]
                            .into(),
                        global_trace_evaluations: vec![EF::zero(); chip.global_width()].into(),
                    },
                )
            })
            .collect(),
    };

    LogupGkrProof {
        circuit_output,
        global_interaction_outputs,
        round_proofs,
        logup_evaluations,
        witness: F::zero(),
    }
}
