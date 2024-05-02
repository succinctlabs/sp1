use anyhow::Result;
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use sp1_core::{
    air::PublicValues,
    stark::{MachineProof, ProgramVerificationError, RiscvAir, ShardProof, StarkGenericConfig},
};
use sp1_recursion_core::{
    air::RecursionPublicValues,
    stark::{RecursionAir, RecursionAirWideDeg3},
};

use crate::{CoreSC, InnerSC, SP1CoreProofData, SP1Proof, SP1ReducedProofData, SP1VerifyingKey};

/// Verify a core proof.
pub fn verify_core_proof(
    shard_proofs: &[ShardProof<CoreSC>],
    vk: &SP1VerifyingKey,
) -> Result<(), ProgramVerificationError<CoreSC>> {
    let core_machine = RiscvAir::machine(CoreSC::default());
    let mut challenger = core_machine.config().challenger();
    let machine_proof = MachineProof {
        shard_proofs: shard_proofs.to_vec(),
    };
    core_machine.verify(&vk.vk, &machine_proof, &mut challenger)?;

    // Verify shard transitions
    for (i, shard_proof) in shard_proofs.iter().enumerate() {
        let public_values = PublicValues::from_vec(shard_proof.public_values.clone());
        // Verify shard transitions
        if i == 0 {
            // If it's the first shard, index should be 1.
            if public_values.shard != BabyBear::one() {
                return Err(ProgramVerificationError::InvalidPublicValues(
                    "first shard not 1",
                ));
            }
            if public_values.start_pc != vk.vk.pc_start {
                return Err(ProgramVerificationError::InvalidPublicValues(
                    "wrong pc_start",
                ));
            }
        } else {
            let prev_shard_proof = &shard_proofs[i - 1];
            let prev_public_values = PublicValues::from_vec(prev_shard_proof.public_values.clone());
            // For non-first shards, the index should be the previous index + 1.
            if public_values.shard != prev_public_values.shard + BabyBear::one() {
                return Err(ProgramVerificationError::InvalidPublicValues(
                    "non incremental shard index",
                ));
            }
            // Start pc should be what the next pc declared in the previous shard was.
            if public_values.start_pc != prev_public_values.next_pc {
                return Err(ProgramVerificationError::InvalidPublicValues("pc mismatch"));
            }
            // Digests and exit code should be the same in all shards.
            if public_values.committed_value_digest != prev_public_values.committed_value_digest
                || public_values.deferred_proofs_digest != prev_public_values.deferred_proofs_digest
                || public_values.exit_code != prev_public_values.exit_code
            {
                return Err(ProgramVerificationError::InvalidPublicValues(
                    "digest or exit code mismatch",
                ));
            }
            // The last shard should be halted. Halt is signaled with next_pc == 0.
            if i == shard_proofs.len() - 1 && public_values.next_pc != BabyBear::zero() {
                return Err(ProgramVerificationError::InvalidPublicValues(
                    "last shard isn't halted",
                ));
            }
            // All non-last shards should not be halted.
            if i != shard_proofs.len() - 1 && public_values.next_pc == BabyBear::zero() {
                return Err(ProgramVerificationError::InvalidPublicValues(
                    "non-last shard is halted",
                ));
            }
        }
    }

    Ok(())
}

/// Verify a reduced proof.
pub fn verify_reduced_proof(
    proof: ShardProof<InnerSC>,
    vk: &SP1VerifyingKey,
) -> Result<(), ProgramVerificationError<CoreSC>> {
    let recursion_machine = RecursionAirWideDeg3::machine(InnerSC::new());
    let mut challenger = recursion_machine.config().challenger();
    let machine_proof = MachineProof {
        shard_proofs: vec![proof.clone()],
    };
    recursion_machine.verify(&vk.vk, &machine_proof, &mut challenger)?;

    let public_values = RecursionPublicValues::from_vec(proof.public_values.clone());

    if public_values.is_complete != BabyBear::one() {
        return Err(ProgramVerificationError::InvalidPublicValues(
            "is_complete is not 1",
        ));
    }

    Ok(())
}
