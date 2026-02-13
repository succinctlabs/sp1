use std::{collections::BTreeSet, iter::once};

use slop_algebra::AbstractField;
use slop_basefold::{BasefoldVerifier, FriConfig};
use slop_multilinear::Point;
use sp1_hypercube::{
    air::MachineAir, septic_digest::SepticDigest, AirOpenedValues, Chip, ChipOpenedValues,
    MachineVerifyingKey, SP1PcsProofInner, ShardOpenedValues, ShardProof, NUM_SP1_COMMITMENTS,
    PROOF_MAX_NUM_PVS,
};
use sp1_primitives::{SP1ExtensionField, SP1Field, SP1GlobalContext};

use crate::dummy::{
    jagged::dummy_pcs_proof, logup_gkr::dummy_gkr_proof, sumcheck::dummy_sumcheck_proof,
};

type EF = SP1ExtensionField;

pub fn dummy_vk() -> MachineVerifyingKey<SP1GlobalContext> {
    MachineVerifyingKey {
        pc_start: [SP1Field::zero(); 3],
        initial_global_cumulative_sum: SepticDigest::zero(),
        preprocessed_commit: [SP1Field::zero(); 8],
        enable_untrusted_programs: SP1Field::zero(),
    }
}

pub fn dummy_shard_proof<A: MachineAir<SP1Field>>(
    shard_chips: BTreeSet<Chip<SP1Field, A>>,
    max_log_row_count: usize,
    fri_config: FriConfig<SP1Field>,
    log_stacking_height: usize,
    log_stacking_height_multiples: &[usize],
    added_cols: &[usize],
) -> ShardProof<SP1GlobalContext, SP1PcsProofInner> {
    let default_verifier =
        BasefoldVerifier::<SP1GlobalContext>::new(fri_config, NUM_SP1_COMMITMENTS);

    let fri_queries = default_verifier.fri_config.num_queries;
    let log_blowup = default_verifier.fri_config.log_blowup;

    let evaluation_proof = dummy_pcs_proof(
        fri_queries,
        max_log_row_count,
        log_stacking_height_multiples,
        log_stacking_height,
        log_blowup,
        once(shard_chips.iter().map(MachineAir::preprocessed_width).filter(|x| *x > 0).collect())
            .chain(once(shard_chips.iter().map(|chip| chip.air.width()).collect::<Vec<_>>()))
            .zip(added_cols.iter().copied())
            .collect(),
    );

    let logup_gkr_proof =
        dummy_gkr_proof::<_, SP1ExtensionField, _>(&shard_chips, max_log_row_count);

    let zerocheck_proof = dummy_sumcheck_proof::<SP1ExtensionField>(max_log_row_count, 4);

    ShardProof {
        public_values: vec![SP1Field::zero(); PROOF_MAX_NUM_PVS],
        main_commitment: [SP1Field::zero(); 8],
        logup_gkr_proof,
        zerocheck_proof,
        opened_values: ShardOpenedValues {
            chips: shard_chips
                .iter()
                .map(|chip| {
                    (
                        chip.name().to_string(),
                        ChipOpenedValues {
                            preprocessed: AirOpenedValues {
                                local: vec![EF::zero(); chip.preprocessed_width()],
                            },
                            main: AirOpenedValues { local: vec![EF::zero(); chip.air.width()] },
                            degree: Point::from_usize(0, max_log_row_count + 1),
                        },
                    )
                })
                .collect(),
        },
        evaluation_proof,
    }
}
