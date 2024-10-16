use std::{borrow::Borrow, path::Path, str::FromStr};

use anyhow::Result;
use num_bigint::BigUint;
use p3_baby_bear::BabyBear;
use p3_field::{AbstractField, PrimeField};
use sp1_core_executor::{subproof::SubproofVerifier, SP1ReduceProof};
use sp1_core_machine::cpu::MAX_CPU_LOG_DEGREE;
use sp1_primitives::{consts::WORD_SIZE, io::SP1PublicValues};

use sp1_recursion_circuit::machine::RootPublicValues;
use sp1_recursion_core::{air::RecursionPublicValues, stark::BabyBearPoseidon2Outer};
use sp1_recursion_gnark_ffi::{
    Groth16Bn254Proof, Groth16Bn254Prover, PlonkBn254Proof, PlonkBn254Prover,
};
use sp1_stark::{
    air::{PublicValues, POSEIDON_NUM_WORDS, PV_DIGEST_NUM_WORDS},
    baby_bear_poseidon2::BabyBearPoseidon2,
    MachineProof, MachineProver, MachineVerificationError, StarkGenericConfig, Word,
};
use thiserror::Error;

use crate::{
    components::SP1ProverComponents,
    utils::{assert_recursion_public_values_valid, assert_root_public_values_valid},
    CoreSC, HashableKey, OuterSC, SP1CoreProofData, SP1Prover, SP1VerifyingKey,
};

#[derive(Error, Debug)]
pub enum PlonkVerificationError {
    #[error(
        "the verifying key does not match the inner plonk bn254 proof's committed verifying key"
    )]
    InvalidVerificationKey,
    #[error(
        "the public values in the sp1 proof do not match the public values in the inner plonk bn254 proof"
    )]
    InvalidPublicValues,
}

#[derive(Error, Debug)]
pub enum Groth16VerificationError {
    #[error(
        "the verifying key does not match the inner groth16 bn254 proof's committed verifying key"
    )]
    InvalidVerificationKey,
    #[error(
        "the public values in the sp1 proof do not match the public values in the inner groth16 bn254 proof"
    )]
    InvalidPublicValues,
}

impl<C: SP1ProverComponents> SP1Prover<C> {
    /// Verify a core proof by verifying the shards, verifying lookup bus, verifying that the
    /// shards are contiguous and complete.
    pub fn verify(
        &self,
        proof: &SP1CoreProofData,
        vk: &SP1VerifyingKey,
    ) -> Result<(), MachineVerificationError<CoreSC>> {
        // First shard has a "CPU" constraint.
        //
        // Assert that the first shard has a "CPU".
        let first_shard = proof.0.first().unwrap();
        if !first_shard.contains_cpu() {
            return Err(MachineVerificationError::MissingCpuInFirstShard);
        }

        // CPU log degree bound constraints.
        //
        // Assert that the CPU log degree does not exceed `MAX_CPU_LOG_DEGREE`. This is to ensure
        // that the lookup argument's multiplicities do not overflow.
        for shard_proof in proof.0.iter() {
            if shard_proof.contains_cpu() {
                let log_degree_cpu = shard_proof.log_degree_cpu();
                if log_degree_cpu > MAX_CPU_LOG_DEGREE {
                    return Err(MachineVerificationError::CpuLogDegreeTooLarge(log_degree_cpu));
                }
            }
        }

        // Shard constraints.
        //
        // Initialization:
        // - Shard should start at one.
        //
        // Transition:
        // - Shard should increment by one for each shard.
        let mut current_shard = BabyBear::zero();
        for shard_proof in proof.0.iter() {
            let public_values: &PublicValues<Word<_>, _> =
                shard_proof.public_values.as_slice().borrow();
            current_shard += BabyBear::one();
            if public_values.shard != current_shard {
                return Err(MachineVerificationError::InvalidPublicValues(
                    "shard index should be the previous shard index + 1 and start at 1",
                ));
            }
        }

        // Execution shard constraints.
        //
        // Initialization:
        // - Execution shard should start at one.
        //
        // Transition:
        // - Execution shard should increment by one for each shard with "CPU".
        // - Execution shard should stay the same for non-CPU shards.
        // - For the other shards, execution shard does not matter.
        let mut current_execution_shard = BabyBear::zero();
        for shard_proof in proof.0.iter() {
            let public_values: &PublicValues<Word<_>, _> =
                shard_proof.public_values.as_slice().borrow();
            if shard_proof.contains_cpu() {
                current_execution_shard += BabyBear::one();
                if public_values.execution_shard != current_execution_shard {
                    return Err(MachineVerificationError::InvalidPublicValues(
                        "execution shard index should be the previous execution shard index + 1 if cpu exists and start at 1",
                    ));
                }
            }
        }

        // Program counter constraints.
        //
        // Initialization:
        // - `start_pc` should start as `vk.start_pc`.
        //
        // Transition:
        // - `next_pc` of the previous shard should equal `start_pc`.
        // - If it's not a shard with "CPU", then `start_pc` equals `next_pc`.
        // - If it's a shard with "CPU", then `start_pc` should never equal zero.
        //
        // Finalization:
        // - `next_pc` should equal zero.
        let mut prev_next_pc = BabyBear::zero();
        for (i, shard_proof) in proof.0.iter().enumerate() {
            let public_values: &PublicValues<Word<_>, _> =
                shard_proof.public_values.as_slice().borrow();
            if i == 0 && public_values.start_pc != vk.vk.pc_start {
                return Err(MachineVerificationError::InvalidPublicValues(
                    "start_pc != vk.start_pc: program counter should start at vk.start_pc",
                ));
            } else if i != 0 && public_values.start_pc != prev_next_pc {
                return Err(MachineVerificationError::InvalidPublicValues(
                    "start_pc != next_pc_prev: start_pc should equal next_pc_prev for all shards",
                ));
            } else if !shard_proof.contains_cpu() && public_values.start_pc != public_values.next_pc
            {
                return Err(MachineVerificationError::InvalidPublicValues(
                    "start_pc != next_pc: start_pc should equal next_pc for non-cpu shards",
                ));
            } else if shard_proof.contains_cpu() && public_values.start_pc == BabyBear::zero() {
                return Err(MachineVerificationError::InvalidPublicValues(
                    "start_pc == 0: execution should never start at halted state",
                ));
            } else if i == proof.0.len() - 1 && public_values.next_pc != BabyBear::zero() {
                return Err(MachineVerificationError::InvalidPublicValues(
                    "next_pc != 0: execution should have halted",
                ));
            }
            prev_next_pc = public_values.next_pc;
        }

        // Exit code constraints.
        //
        // - In every shard, the exit code should be zero.
        for shard_proof in proof.0.iter() {
            let public_values: &PublicValues<Word<_>, _> =
                shard_proof.public_values.as_slice().borrow();
            if public_values.exit_code != BabyBear::zero() {
                return Err(MachineVerificationError::InvalidPublicValues(
                    "exit_code != 0: exit code should be zero for all shards",
                ));
            }
        }

        // Memory initialization & finalization constraints.
        //
        // Initialization:
        // - `previous_init_addr_bits` should be zero.
        // - `previous_finalize_addr_bits` should be zero.
        //
        // Transition:
        // - For all shards, `previous_init_addr_bits` should equal `last_init_addr_bits` of the
        //   previous shard.
        // - For all shards, `previous_finalize_addr_bits` should equal `last_finalize_addr_bits` of
        //   the previous shard.
        // - For shards without "MemoryInit", `previous_init_addr_bits` should equal
        //   `last_init_addr_bits`.
        // - For shards without "MemoryFinalize", `previous_finalize_addr_bits` should equal
        //   `last_finalize_addr_bits`.
        let mut last_init_addr_bits_prev = [BabyBear::zero(); 32];
        let mut last_finalize_addr_bits_prev = [BabyBear::zero(); 32];
        for shard_proof in proof.0.iter() {
            let public_values: &PublicValues<Word<_>, _> =
                shard_proof.public_values.as_slice().borrow();
            if public_values.previous_init_addr_bits != last_init_addr_bits_prev {
                return Err(MachineVerificationError::InvalidPublicValues(
                    "previous_init_addr_bits != last_init_addr_bits_prev",
                ));
            } else if public_values.previous_finalize_addr_bits != last_finalize_addr_bits_prev {
                return Err(MachineVerificationError::InvalidPublicValues(
                    "last_init_addr_bits != last_finalize_addr_bits_prev",
                ));
            } else if !shard_proof.contains_global_memory_init()
                && public_values.previous_init_addr_bits != public_values.last_init_addr_bits
            {
                return Err(MachineVerificationError::InvalidPublicValues(
                    "previous_init_addr_bits != last_init_addr_bits",
                ));
            } else if !shard_proof.contains_global_memory_finalize()
                && public_values.previous_finalize_addr_bits
                    != public_values.last_finalize_addr_bits
            {
                return Err(MachineVerificationError::InvalidPublicValues(
                    "previous_finalize_addr_bits != last_finalize_addr_bits",
                ));
            }
            last_init_addr_bits_prev = public_values.last_init_addr_bits;
            last_finalize_addr_bits_prev = public_values.last_finalize_addr_bits;
        }

        // Digest constraints.
        //
        // Initialization:
        // - `committed_value_digest` should be zero.
        // - `deferred_proofs_digest` should be zero.
        //
        // Transition:
        // - If `committed_value_digest_prev` is not zero, then `committed_value_digest` should equal
        //  `committed_value_digest_prev`. Otherwise, `committed_value_digest` should equal zero.
        // - If `deferred_proofs_digest_prev` is not zero, then `deferred_proofs_digest` should
        //   equal
        //  `deferred_proofs_digest_prev`. Otherwise, `deferred_proofs_digest` should equal zero.
        // - If it's not a shard with "CPU", then `committed_value_digest` should not change from the
        //  previous shard.
        // - If it's not a shard with "CPU", then `deferred_proofs_digest` should not change from
        //   the
        //  previous shard.
        let zero_committed_value_digest =
            [Word([BabyBear::zero(); WORD_SIZE]); PV_DIGEST_NUM_WORDS];
        let zero_deferred_proofs_digest = [BabyBear::zero(); POSEIDON_NUM_WORDS];
        let mut committed_value_digest_prev = zero_committed_value_digest;
        let mut deferred_proofs_digest_prev = zero_deferred_proofs_digest;
        for shard_proof in proof.0.iter() {
            let public_values: &PublicValues<Word<_>, _> =
                shard_proof.public_values.as_slice().borrow();
            if committed_value_digest_prev != zero_committed_value_digest
                && public_values.committed_value_digest != committed_value_digest_prev
            {
                return Err(MachineVerificationError::InvalidPublicValues(
                    "committed_value_digest != committed_value_digest_prev",
                ));
            } else if deferred_proofs_digest_prev != zero_deferred_proofs_digest
                && public_values.deferred_proofs_digest != deferred_proofs_digest_prev
            {
                return Err(MachineVerificationError::InvalidPublicValues(
                    "deferred_proofs_digest != deferred_proofs_digest_prev",
                ));
            } else if !shard_proof.contains_cpu()
                && public_values.committed_value_digest != committed_value_digest_prev
            {
                return Err(MachineVerificationError::InvalidPublicValues(
                    "committed_value_digest != committed_value_digest_prev",
                ));
            } else if !shard_proof.contains_cpu()
                && public_values.deferred_proofs_digest != deferred_proofs_digest_prev
            {
                return Err(MachineVerificationError::InvalidPublicValues(
                    "deferred_proofs_digest != deferred_proofs_digest_prev",
                ));
            }
            committed_value_digest_prev = public_values.committed_value_digest;
            deferred_proofs_digest_prev = public_values.deferred_proofs_digest;
        }

        // Verify that the number of shards is not too large.
        if proof.0.len() > 1 << 16 {
            return Err(MachineVerificationError::TooManyShards);
        }

        // Verify the shard proof.
        let mut challenger = self.core_prover.config().challenger();
        let machine_proof = MachineProof { shard_proofs: proof.0.to_vec() };
        self.core_prover.machine().verify(&vk.vk, &machine_proof, &mut challenger)?;

        Ok(())
    }

    /// Verify a compressed proof.
    pub fn verify_compressed(
        &self,
        proof: &SP1ReduceProof<BabyBearPoseidon2>,
        vk: &SP1VerifyingKey,
    ) -> Result<(), MachineVerificationError<CoreSC>> {
        let SP1ReduceProof { vk: compress_vk, proof } = proof;
        let mut challenger = self.compress_prover.config().challenger();
        let machine_proof = MachineProof { shard_proofs: vec![proof.clone()] };
        self.compress_prover.machine().verify(compress_vk, &machine_proof, &mut challenger)?;

        // Validate public values
        let public_values: &RecursionPublicValues<_> = proof.public_values.as_slice().borrow();
        assert_recursion_public_values_valid(
            self.compress_prover.machine().config(),
            public_values,
        );

        if self.vk_verification && !self.allowed_vk_map.contains_key(&compress_vk.hash_babybear()) {
            return Err(MachineVerificationError::InvalidVerificationKey);
        }

        // `is_complete` should be 1. In the reduce program, this ensures that the proof is fully
        // reduced.
        if public_values.is_complete != BabyBear::one() {
            return Err(MachineVerificationError::InvalidPublicValues("is_complete is not 1"));
        }

        // Verify that the proof is for the sp1 vkey we are expecting.
        let vkey_hash = vk.hash_babybear();
        if public_values.sp1_vk_digest != vkey_hash {
            return Err(MachineVerificationError::InvalidPublicValues("sp1 vk hash mismatch"));
        }

        Ok(())
    }

    /// Verify a shrink proof.
    pub fn verify_shrink(
        &self,
        proof: &SP1ReduceProof<BabyBearPoseidon2>,
        vk: &SP1VerifyingKey,
    ) -> Result<(), MachineVerificationError<CoreSC>> {
        let mut challenger = self.shrink_prover.config().challenger();
        let machine_proof = MachineProof { shard_proofs: vec![proof.proof.clone()] };
        self.shrink_prover.machine().verify(&proof.vk, &machine_proof, &mut challenger)?;

        // Validate public values
        let public_values: &RecursionPublicValues<_> =
            proof.proof.public_values.as_slice().borrow();
        assert_recursion_public_values_valid(
            self.compress_prover.machine().config(),
            public_values,
        );

        if self.vk_verification && !self.allowed_vk_map.contains_key(&proof.vk.hash_babybear()) {
            return Err(MachineVerificationError::InvalidVerificationKey);
        }

        // Verify that the proof is for the sp1 vkey we are expecting.
        let vkey_hash = vk.hash_babybear();
        if public_values.sp1_vk_digest != vkey_hash {
            return Err(MachineVerificationError::InvalidPublicValues("sp1 vk hash mismatch"));
        }

        Ok(())
    }

    /// Verify a wrap bn254 proof.
    pub fn verify_wrap_bn254(
        &self,
        proof: &SP1ReduceProof<BabyBearPoseidon2Outer>,
        vk: &SP1VerifyingKey,
    ) -> Result<(), MachineVerificationError<OuterSC>> {
        let mut challenger = self.wrap_prover.config().challenger();
        let machine_proof = MachineProof { shard_proofs: vec![proof.proof.clone()] };

        let wrap_vk = self.wrap_vk.get().expect("Wrap verifier key not set");
        self.wrap_prover.machine().verify(wrap_vk, &machine_proof, &mut challenger)?;

        // Validate public values
        let public_values: &RootPublicValues<_> = proof.proof.public_values.as_slice().borrow();
        assert_root_public_values_valid(self.shrink_prover.machine().config(), public_values);

        // Verify that the proof is for the sp1 vkey we are expecting.
        let vkey_hash = vk.hash_babybear();
        if *public_values.sp1_vk_digest() != vkey_hash {
            return Err(MachineVerificationError::InvalidPublicValues("sp1 vk hash mismatch"));
        }

        Ok(())
    }

    /// Verifies a PLONK proof using the circuit artifacts in the build directory.
    pub fn verify_plonk_bn254(
        &self,
        proof: &PlonkBn254Proof,
        vk: &SP1VerifyingKey,
        public_values: &SP1PublicValues,
        build_dir: &Path,
    ) -> Result<()> {
        let prover = PlonkBn254Prover::new();

        let vkey_hash = BigUint::from_str(&proof.public_inputs[0])?;
        let committed_values_digest = BigUint::from_str(&proof.public_inputs[1])?;

        // Verify the proof with the corresponding public inputs.
        prover.verify(proof, &vkey_hash, &committed_values_digest, build_dir);

        verify_plonk_bn254_public_inputs(vk, public_values, &proof.public_inputs)?;

        Ok(())
    }

    /// Verifies a Groth16 proof using the circuit artifacts in the build directory.
    pub fn verify_groth16_bn254(
        &self,
        proof: &Groth16Bn254Proof,
        vk: &SP1VerifyingKey,
        public_values: &SP1PublicValues,
        build_dir: &Path,
    ) -> Result<()> {
        let prover = Groth16Bn254Prover::new();

        let vkey_hash = BigUint::from_str(&proof.public_inputs[0])?;
        let committed_values_digest = BigUint::from_str(&proof.public_inputs[1])?;

        // Verify the proof with the corresponding public inputs.
        prover.verify(proof, &vkey_hash, &committed_values_digest, build_dir);

        verify_groth16_bn254_public_inputs(vk, public_values, &proof.public_inputs)?;

        Ok(())
    }
}

/// Verify the vk_hash and public_values_hash in the public inputs of the PlonkBn254Proof match the
/// expected values.
pub fn verify_plonk_bn254_public_inputs(
    vk: &SP1VerifyingKey,
    public_values: &SP1PublicValues,
    plonk_bn254_public_inputs: &[String],
) -> Result<()> {
    let expected_vk_hash = BigUint::from_str(&plonk_bn254_public_inputs[0])?;
    let expected_public_values_hash = BigUint::from_str(&plonk_bn254_public_inputs[1])?;

    let vk_hash = vk.hash_bn254().as_canonical_biguint();
    if vk_hash != expected_vk_hash {
        return Err(PlonkVerificationError::InvalidVerificationKey.into());
    }

    let public_values_hash = public_values.hash_bn254();
    if public_values_hash != expected_public_values_hash {
        return Err(PlonkVerificationError::InvalidPublicValues.into());
    }

    Ok(())
}

/// Verify the vk_hash and public_values_hash in the public inputs of the Groth16Bn254Proof match
/// the expected values.
pub fn verify_groth16_bn254_public_inputs(
    vk: &SP1VerifyingKey,
    public_values: &SP1PublicValues,
    groth16_bn254_public_inputs: &[String],
) -> Result<()> {
    let expected_vk_hash = BigUint::from_str(&groth16_bn254_public_inputs[0])?;
    let expected_public_values_hash = BigUint::from_str(&groth16_bn254_public_inputs[1])?;

    let vk_hash = vk.hash_bn254().as_canonical_biguint();
    if vk_hash != expected_vk_hash {
        return Err(Groth16VerificationError::InvalidVerificationKey.into());
    }

    let public_values_hash = public_values.hash_bn254();
    if public_values_hash != expected_public_values_hash {
        return Err(Groth16VerificationError::InvalidPublicValues.into());
    }

    Ok(())
}

impl<C: SP1ProverComponents> SubproofVerifier for &SP1Prover<C> {
    fn verify_deferred_proof(
        &self,
        proof: &sp1_core_machine::reduce::SP1ReduceProof<BabyBearPoseidon2>,
        vk: &sp1_stark::StarkVerifyingKey<BabyBearPoseidon2>,
        vk_hash: [u32; 8],
        committed_value_digest: [u32; 8],
    ) -> Result<(), MachineVerificationError<BabyBearPoseidon2>> {
        // Check that the vk hash matches the vk hash from the input.
        if vk.hash_u32() != vk_hash {
            return Err(MachineVerificationError::InvalidPublicValues(
                "vk hash from syscall does not match vkey from input",
            ));
        }
        // Check that proof is valid.
        self.verify_compressed(
            &SP1ReduceProof { vk: proof.vk.clone(), proof: proof.proof.clone() },
            &SP1VerifyingKey { vk: vk.clone() },
        )?;
        // Check that the committed value digest matches the one from syscall
        let public_values: &RecursionPublicValues<_> =
            proof.proof.public_values.as_slice().borrow();
        for (i, word) in public_values.committed_value_digest.iter().enumerate() {
            if *word != committed_value_digest[i].into() {
                return Err(MachineVerificationError::InvalidPublicValues(
                    "committed_value_digest does not match",
                ));
            }
        }
        Ok(())
    }
}
