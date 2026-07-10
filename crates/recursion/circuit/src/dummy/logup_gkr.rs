use std::collections::BTreeSet;

use slop_air::BaseAir;
use slop_algebra::{ExtensionField, Field};
use slop_multilinear::Point;
use sp1_hypercube::{
    air::MachineAir, log2_ceil_usize, Chip, ChipEvaluation, LogUpEvaluations, LogUpGkrOutput,
    LogupGkrProof, LogupGkrRoundProof,
};

use super::sumcheck::dummy_sumcheck_proof;

pub fn dummy_gkr_proof<F: Field, EF: ExtensionField<F>, A: MachineAir<F>>(
    shard_chips: &BTreeSet<Chip<F, A>>,
    log_max_row_height: usize,
) -> LogupGkrProof<F, EF> {
    let total_num_interactions =
        shard_chips.iter().map(|chip| chip.num_interactions()).sum::<usize>();
    let number_of_interaction_variables = log2_ceil_usize(total_num_interactions);
    // The circuit output is the top `level-1` layer: always a single pair of fractions.
    let output_size = 2;
    let circuit_output = LogUpGkrOutput {
        numerator: vec![EF::zero(); output_size].into(),
        denominator: vec![EF::zero(); output_size].into(),
    };

    // The GKR tree runs `number_of_interaction_variables` interaction-combining rounds followed by
    // `log_max_row_height - 1` row rounds; round `i` (0-indexed) has `i + 1` sumcheck variables.
    let num_rounds = number_of_interaction_variables + log_max_row_height - 1;
    let round_proofs = (0..num_rounds)
        .map(|i| LogupGkrRoundProof {
            numerator_0: EF::zero(),
            numerator_1: EF::zero(),
            denominator_0: EF::zero(),
            denominator_1: EF::zero(),
            sumcheck_proof: dummy_sumcheck_proof::<EF>(i + 1, 3),
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
                        preprocessed_trace_evaluations: if chip.preprocessed_width() > 0 {
                            Some(vec![EF::zero(); chip.preprocessed_width()].into())
                        } else {
                            None
                        },
                    },
                )
            })
            .collect(),
    };

    LogupGkrProof { circuit_output, round_proofs, logup_evaluations, witness: F::zero() }
}
