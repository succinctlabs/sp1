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
    let output_size = 1 << (log2_ceil_usize(total_num_interactions) + 1);
    let circuit_output = LogUpGkrOutput {
        numerator: vec![EF::zero(); output_size].into(),
        denominator: vec![EF::zero(); output_size].into(),
    };

    let round_proofs = (0..log_max_row_height - 1)
        .map(|i| LogupGkrRoundProof {
            numerator_0: EF::zero(),
            numerator_1: EF::zero(),
            denominator_0: EF::zero(),
            denominator_1: EF::zero(),
            sumcheck_proof: dummy_sumcheck_proof::<EF>(
                i + log2_ceil_usize(total_num_interactions) + 1,
                3,
            ),
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
