use crate::{
    build::{groth16_bn254_artifacts_dev_dir, plonk_bn254_artifacts_dev_dir, use_development_mode},
    utils::{is_recursion_public_values_valid, is_root_public_values_valid},
    CoreSC, CpuSP1ProverComponents, RecursionSC, SP1ProverComponents, ShrinkSC, WrapSC,
};
use anyhow::{anyhow, Result};
use num_bigint::BigUint;
use slop_algebra::{AbstractField, PrimeField, PrimeField32};
use sp1_core_executor::SP1RecursionProof;
use sp1_core_machine::riscv::{RiscvAir, MAX_LOG_NUMBER_OF_SHARDS};
use sp1_hypercube::{
    air::{PublicValues, SP1CorePublicValues, POSEIDON_NUM_WORDS, PV_DIGEST_NUM_WORDS},
    koalabears_to_bn254, HashableKey, Machine, MachineVerifier, MachineVerifierConfigError,
    MachineVerifierError, MachineVerifyingKey, SP1InnerPcs, SP1OuterPcs, SP1PcsProofInner,
    SP1PcsProofOuter, SP1VerifyingKey, SP1WrapProof, PROOF_MAX_NUM_PVS,
};
use sp1_primitives::{
    io::{blake3_hash, SP1PublicValues},
    SP1ExtensionField, SP1Field, SP1GlobalContext, SP1OuterGlobalContext,
};
use sp1_recursion_circuit::machine::RootPublicValues;
use sp1_recursion_executor::RecursionPublicValues;
use sp1_recursion_gnark_ffi::{
    Groth16Bn254Proof, Groth16Bn254Prover, PlonkBn254Proof, PlonkBn254Prover,
};
pub use sp1_verifier::VerifierRecursionVks;
use sp1_verifier::{Groth16Verifier, PlonkVerifier, GROTH16_VK_BYTES, PLONK_VK_BYTES};
use std::{borrow::Borrow, collections::BTreeMap, str::FromStr};
use thiserror::Error;

use crate::{worker::proof_sort_key, SP1CoreProofData};

#[derive(Error, Debug)]
pub enum PlonkVerificationError {
    #[error(
        "the verifying key does not match the inner plonk bn254 proof's committed verifying key"
    )]
    InvalidVerificationKey,
    #[error(
        "the public values in the sp1 proof do not match the public values in the inner plonk
bn254 proof"
    )]
    InvalidPublicValues,
}

#[derive(Error, Debug)]
pub enum Groth16VerificationError {
    #[error(
        "the verifying key does not match the inner groth16 bn254 proof's committed verifying
key"
    )]
    InvalidVerificationKey,
    #[error(
        "the public values in the sp1 proof do not match the public values in the inner groth16
bn254 proof"
    )]
    InvalidPublicValues,
}

/// The verifying key for the program wrapping an SP1 proof into a SNARK friendly format.
#[cfg(not(feature = "mprotect"))]
pub const WRAP_VK_BYTES: &[u8] = include_bytes!("../wrap_vk.bin");
#[cfg(feature = "mprotect")]
pub const WRAP_VK_BYTES: &[u8] = include_bytes!("../wrap_vk_mprotect.bin");

#[derive(Clone)]
pub struct SP1Verifier {
    pub core: MachineVerifier<SP1GlobalContext, CoreSC>,
    pub compress: MachineVerifier<SP1GlobalContext, RecursionSC>,
    pub shrink: MachineVerifier<SP1GlobalContext, ShrinkSC>,
    pub wrap: MachineVerifier<SP1OuterGlobalContext, WrapSC>,
    pub recursion_vks: VerifierRecursionVks,
    pub shrink_vk: Option<MachineVerifyingKey<SP1GlobalContext>>,
    pub wrap_vk: MachineVerifyingKey<SP1OuterGlobalContext>,
}

impl SP1Verifier {
    pub fn new(recursion_vks: VerifierRecursionVks) -> Self {
        Self::new_with_machine(recursion_vks, RiscvAir::machine())
    }

    pub fn new_with_machine(
        recursion_vks: VerifierRecursionVks,
        machine: Machine<SP1Field, RiscvAir<SP1Field>>,
    ) -> Self {
        // Get the verifiers from the components.
        let core = CpuSP1ProverComponents::core_verifier(machine);
        let compress = CpuSP1ProverComponents::compress_verifier();
        let shrink = CpuSP1ProverComponents::shrink_verifier();
        let wrap = CpuSP1ProverComponents::wrap_verifier();

        // Get the wrap vk from the associated constant.
        let wrap_vk = bincode::deserialize(WRAP_VK_BYTES).unwrap();

        Self { core, compress, shrink, wrap, recursion_vks, shrink_vk: None, wrap_vk }
    }

    pub fn vk_verification(&self) -> bool {
        self.recursion_vks.vk_verification()
    }

    pub fn set_shrink_vk(&mut self, shrink_vk: MachineVerifyingKey<SP1GlobalContext>) {
        self.shrink_vk = Some(shrink_vk);
    }

    /// Verify a core proof by verifying the shards, verifying lookup bus, verifying that the
    /// shards are contiguous and complete. Some of the public values verification is inside the
    /// `eval_public_values` function, which is a part of the core shard proof.
    pub fn verify(
        &self,
        proof: &SP1CoreProofData,
        vk: &SP1VerifyingKey,
    ) -> Result<(), MachineVerifierConfigError<SP1GlobalContext, SP1InnerPcs>> {
        let SP1VerifyingKey { vk } = vk;

        if proof.0.is_empty() {
            return Err(MachineVerifierError::EmptyProof);
        }

        // Assert that all the shard proofs have correct public values length.
        for shard_proof in proof.0.iter() {
            if shard_proof.public_values.len() != PROOF_MAX_NUM_PVS {
                return Err(MachineVerifierError::InvalidPublicValues(
                    "invalid public values length",
                ));
            }
        }

        // Chunk-level structure and within-chunk timestamp constraints.
        let public_values_per_shard = proof
            .0
            .iter()
            .map(|shard_proof| {
                let public_values: &PublicValues<[_; 4], [_; 3], [_; 4], _> =
                    shard_proof.public_values.as_slice().borrow();
                public_values
            })
            .collect::<Vec<_>>();
        check_core_chunk_structure(&public_values_per_shard)
            .map_err(MachineVerifierError::InvalidPublicValues)?;

        // The first chunk's prev_merkle_root must be the program's initial memory image (the
        // merkle-root analogue of pc_start == vk.pc_start; the chain is checked above).
        if public_values_per_shard[0].prev_merkle_root != vk.initial_memory_root {
            return Err(MachineVerifierError::InvalidPublicValues(
                "prev_merkle_root != vk.initial_memory_root: execution must start from the program's initial memory image",
            ));
        }

        // Program counter constraints.
        //
        // Initialization:
        // - `pc_start` should start as `vk.pc_start`.
        //
        // Transition:
        // - `next_pc` of a shard should equal to `pc_start` of the next shard.
        //
        // Finalization:
        // - `next_pc` should equal `HALT_PC`.
        //
        // Internal Constraints:
        // - Inside the shard proof, it's constrained that `pc_start` and `next_pc` are composed of
        // valid u16 limbs, and that in a non-execution shard, `pc_start` and `next_pc` are equal.
        // - We include some of these checks inside the verify function for additional verification.
        let mut prev_next_pc = vk.pc_start;
        let halt_pc = [
            SP1Field::from_canonical_u64(sp1_core_executor::HALT_PC),
            SP1Field::zero(),
            SP1Field::zero(),
        ];
        for (i, shard_proof) in proof.0.iter().enumerate() {
            let public_values: &PublicValues<[_; 4], [_; 3], [_; 4], _> =
                shard_proof.public_values.as_slice().borrow();
            if public_values.pc_start != prev_next_pc {
                if i == 0 {
                    return Err(MachineVerifierError::InvalidPublicValues(
                        "pc_start != vk.pc_start: program counter should start at vk.pc_start",
                    ));
                } else {
                    tracing::debug!("checking shard {}/{}", i, proof.0.len());
                    tracing::debug!("pc_start: {:?}", public_values.pc_start);
                    tracing::debug!("prev_next_pc: {:?}", prev_next_pc);
                    return Err(MachineVerifierError::InvalidPublicValues(
                        "pc_start != prev_next_pc: pc_start should equal prev_next_pc for all shards",
                    ));
                }
            }
            // These checks below are already done in the shard proof, but done additionally.
            if public_values.is_execution_shard != SP1Field::one()
                && public_values.pc_start != public_values.next_pc
            {
                return Err(MachineVerifierError::InvalidPublicValues(
                    "pc_start != next_pc: pc_start should equal next_pc for non-execution shards",
                ));
            }
            prev_next_pc = public_values.next_pc;
        }
        if prev_next_pc != halt_pc {
            return Err(MachineVerifierError::InvalidPublicValues(
                "next_pc != HALT_PC: execution should have halted",
            ));
        }

        // Exit code constraints.
        //
        // Initialization
        // - The `prev_exit_code` of the first shard must be zero.
        //
        // Transition
        // - The `exit_code` of the shard must be the `prev_exit_code` of the next shard.
        //
        // Internal Constraints:
        // - Inside the shard proof, it is constrained that `prev_exit_code` and `exit_code` must
        // equal to each other if the shard is not an execution shard.
        // - Inside the shard proof, it is constrained that if `prev_exit_code` is non-zero, then
        // `exit_code` must be equal to the `prev_exit_code`.
        // - We include these checks inside the verify function for additional verification.
        let mut prev_exit_code = SP1Field::zero();
        for shard_proof in proof.0.iter() {
            let public_values: &PublicValues<[_; 4], [_; 3], [_; 4], _> =
                shard_proof.public_values.as_slice().borrow();
            if public_values.prev_exit_code != prev_exit_code {
                return Err(MachineVerifierError::InvalidPublicValues(
                    "public_values.prev_exit_code != prev_exit_code: prev_exit_code does not match previous shard's exit_code",
                ));
            }
            // These checks below are already done in the shard proof, but done additionally.
            if public_values.is_execution_shard != SP1Field::one()
                && public_values.prev_exit_code != public_values.exit_code
            {
                return Err(MachineVerifierError::InvalidPublicValues(
                    "prev_exit_code != exit_code: exit code should be same in non-execution shards",
                ));
            }
            if public_values.prev_exit_code != SP1Field::zero()
                && public_values.prev_exit_code != public_values.exit_code
            {
                return Err(MachineVerifierError::InvalidPublicValues(
                    "prev_exit_code != exit_code: exit code should change at most once",
                ));
            }
            prev_exit_code = public_values.exit_code;
        }

        // Proof nonce constraints.
        //
        // Proof nonce value should be same across all shards
        let public_values_first_shard: &PublicValues<[_; 4], [_; 3], [_; 4], _> =
            proof.0.first().unwrap().public_values.as_slice().borrow();
        let proof_nonce_first_shard = public_values_first_shard.proof_nonce;
        for shard_proof in proof.0[1..].iter() {
            let public_values: &PublicValues<[_; 4], [_; 3], [_; 4], _> =
                shard_proof.public_values.as_slice().borrow();
            if public_values.proof_nonce != proof_nonce_first_shard {
                return Err(MachineVerifierError::InvalidPublicValues(
                    "proof_nonce != proof_nonce_first_shard",
                ));
            }
        }

        // Public values and program configuration for untrusted programs.
        // Constraints:
        // - `enable_trap_handler` is equal between the `vk` and the public values.
        // - `trap_context` is equal between the `vk` and the public values.
        // - `untrusted_memory` is equal between the `vk` and the public values.
        #[cfg(feature = "mprotect")]
        for shard_proof in proof.0.iter() {
            let public_values: &PublicValues<[_; 4], [_; 3], [_; 4], _> =
                shard_proof.public_values.as_slice().borrow();

            if public_values.trap_context != vk.untrusted_config.trap_context {
                return Err(MachineVerifierError::InvalidPublicValues(
                    "trap_context values mismatch",
                ));
            }

            if public_values.untrusted_memory != vk.untrusted_config.untrusted_memory {
                return Err(MachineVerifierError::InvalidPublicValues(
                    "untrusted_memory values mismatch",
                ));
            }

            if public_values.enable_trap_handler != vk.untrusted_config.enable_trap_handler {
                return Err(MachineVerifierError::InvalidPublicValues(
                    "enable_trap_handler values mismatch",
                ));
            }
        }

        // Digest constraints.
        //
        // Initialization:
        // - `prev_committed_value_digest` should be zero.
        // - `prev_deferred_proofs_digest` should be zero.
        // - `prev_commit_syscall` should be zero.
        // - `prev_commit_deferred_syscall` should be zero.
        //
        // Transition:
        // - `committed_value_digest` must equal the next shard's `prev_committed_value_digest`.
        // - `deferred_proofs_digest` must equal the next shard's `prev_deferred_proofs_digest`.
        // - `commit_syscall` must equal the next shard's `prev_commit_syscall`.
        // - `commit_deferred_syscall` must equal the next shard's `prev_commit_deferred_syscall`.
        //
        // Finalization:
        // - The last `commit_syscall` should equal one.
        // - The last `commit_deferred_syscall` should equal one.
        //
        // Internal Constraints for `committed_value_digest` and `commit_syscall`:
        // - The `prev_committed_value_digest` are of valid bytes.
        // - The `committed_value_digest` are of valid bytes.
        // - If the `COMMIT` syscall was called in the shard, then `commit_syscall == 1`.
        // - `prev_commit_syscall` and `commit_syscall` are boolean.
        // - If `prev_commit_syscall == 1`, then `commit_syscall == 1`.
        // - In a non-execution shard, `prev_commit_syscall == commit_syscall`.
        // - If the shard isn't an execution shard, or has `prev_commit_syscall == 1`, or if
        // `prev_committed_value_digest` has a non-zero byte inside it, then
        // `prev_committed_value_digest == committed_value_digest`.
        //
        // Internal Constraints for `deferred_proofs_digest` and `commit_deferred_syscall`:
        // - If `COMMIT_DEFERRED_PROOFS` syscall was called, `commit_deferred_syscall == 1`.
        // - `prev_commit_deferred_syscall` and `commit_deferred_syscall` are boolean.
        // - If `prev_commit_deferred_syscall == 1`, then `commit_deferred_syscall == 1`.
        // - In a non-execution shard, `prev_commit_deferred_syscall == commit_deferred_syscall`.
        // - If the shard isn't an execution shard, or has `prev_commit_deferred_syscall == 1`, or
        // if `prev_deferred_proofs_digest` has a non-zero limb inside it, then
        // `prev_deferred_proofs_digest == deferred_proofs_digest`.
        let zero_committed_value_digest = [[SP1Field::zero(); 4]; PV_DIGEST_NUM_WORDS];
        let zero_deferred_proofs_digest = [SP1Field::zero(); POSEIDON_NUM_WORDS];
        let mut commit_syscall_prev = SP1Field::zero();
        let mut commit_deferred_syscall_prev = SP1Field::zero();
        let mut committed_value_digest_prev = zero_committed_value_digest;
        let mut deferred_proofs_digest_prev = zero_deferred_proofs_digest;
        for shard_proof in proof.0.iter() {
            let public_values: &PublicValues<[_; 4], [_; 3], [_; 4], _> =
                shard_proof.public_values.as_slice().borrow();
            if public_values.prev_committed_value_digest != committed_value_digest_prev {
                return Err(MachineVerifierError::InvalidPublicValues(
                    "prev_committed_value_digest doesn't equal the previous shard's committed_value_digest",
                ));
            }
            if public_values.prev_deferred_proofs_digest != deferred_proofs_digest_prev {
                return Err(MachineVerifierError::InvalidPublicValues(
                    "prev_deferred_proofs_digest doesn't equal the previous shard's deferred_proofs_digest",
                ));
            }
            if public_values.prev_commit_syscall != commit_syscall_prev {
                return Err(MachineVerifierError::InvalidPublicValues(
                    "prev_commit_syscall doesn't equal the previous shard's commit_syscall",
                ));
            }
            if public_values.prev_commit_deferred_syscall != commit_deferred_syscall_prev {
                return Err(MachineVerifierError::InvalidPublicValues(
                    "prev_commit_deferred_syscall doesn't equal the previous shard's commit_deferred_syscall",
                ));
            }
            committed_value_digest_prev = public_values.committed_value_digest;
            deferred_proofs_digest_prev = public_values.deferred_proofs_digest;
            commit_syscall_prev = public_values.commit_syscall;
            commit_deferred_syscall_prev = public_values.commit_deferred_syscall;
        }
        if commit_syscall_prev != SP1Field::one() {
            return Err(MachineVerifierError::InvalidPublicValues(
                "COMMIT syscall was never called",
            ));
        }
        if commit_deferred_syscall_prev != SP1Field::one() {
            return Err(MachineVerifierError::InvalidPublicValues(
                "COMMIT_DEFERRED_PROOFS syscall was never called",
            ));
        }

        // Verify that the number of shards is not too large.
        if proof.0.len() >= 1 << MAX_LOG_NUMBER_OF_SHARDS {
            return Err(MachineVerifierError::TooManyShards);
        }

        // Verify the shard proofs per trace chunk.
        verify_core_shards(&self.core, vk, proof)?;

        Ok(())
    }

    /// Verify a compressed proof.
    pub fn verify_compressed(
        &self,
        proof: &SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>,
        vk: &SP1VerifyingKey,
    ) -> Result<(), MachineVerifierConfigError<SP1GlobalContext, SP1InnerPcs>> {
        let SP1RecursionProof { vk: compress_vk, proof, vk_merkle_proof } = proof;
        let mut challenger = self.compress.challenger();
        compress_vk.observe_into(&mut challenger);

        // Check the public values length.
        if proof.public_values.len() != PROOF_MAX_NUM_PVS {
            return Err(MachineVerifierError::InvalidPublicValues("invalid public values length"));
        }

        // Verify the shard proof.
        self.compress
            .verify_shard(compress_vk, proof, &mut challenger)
            .map_err(MachineVerifierError::InvalidShardProof)?;

        // Validate the public values.
        let public_values: &RecursionPublicValues<_> = proof.public_values.as_slice().borrow();

        // The `digest` is the correct hash of the recursion public values.
        if !is_recursion_public_values_valid(public_values) {
            return Err(MachineVerifierError::InvalidPublicValues(
                "recursion public values are invalid",
            ));
        }

        // The `vk_root` is the expected `vk_root`.
        if public_values.vk_root != self.recursion_vks.root() {
            return Err(MachineVerifierError::InvalidPublicValues("vk_root mismatch"));
        }

        // If `vk_verification` is on, check the `vk` is within the expected list of `vk`'s.
        // This `vk_verification` must be only turned off for testing purposes.
        if self.vk_verification() && !self.recursion_vks.verify(vk_merkle_proof, compress_vk) {
            return Err(MachineVerifierError::InvalidVerificationKey);
        }

        // `is_complete` should be 1. This ensures that the proof is fully reduced.
        if public_values.is_complete != SP1Field::one() {
            return Err(MachineVerifierError::InvalidPublicValues("is_complete is not 1"));
        }

        // Verify that the proof is for the sp1 vkey we are expecting.
        let vkey_hash = vk.hash_koalabear();
        if public_values.sp1_vk_digest != vkey_hash {
            return Err(MachineVerifierError::InvalidPublicValues("sp1 vk hash mismatch"));
        }

        Ok(())
    }

    /// Verify a shrink proof.
    pub fn verify_shrink(
        &self,
        proof: &SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>,
        vk: &SP1VerifyingKey,
    ) -> Result<(), MachineVerifierConfigError<SP1GlobalContext, SP1InnerPcs>> {
        if self.shrink_vk.is_none() {
            return Err(MachineVerifierError::UninitializedVerificationKey);
        }
        let shrink_vk = self.shrink_vk.as_ref().unwrap();
        if proof.vk != *shrink_vk {
            return Err(MachineVerifierError::InvalidVerificationKey);
        }

        let SP1RecursionProof { vk: _, proof, vk_merkle_proof } = proof;
        let mut challenger = self.shrink.challenger();
        shrink_vk.observe_into(&mut challenger);

        // Check the public values length.
        if proof.public_values.len() != PROOF_MAX_NUM_PVS {
            return Err(MachineVerifierError::InvalidPublicValues("invalid public values length"));
        }

        // Verify the shard proof.
        self.shrink
            .verify_shard(shrink_vk, proof, &mut challenger)
            .map_err(MachineVerifierError::InvalidShardProof)?;

        // Validate public values.
        let public_values: &RecursionPublicValues<_> = proof.public_values.as_slice().borrow();

        // The `digest` is the correct hash of the recursion public values.
        if !is_recursion_public_values_valid(public_values) {
            return Err(MachineVerifierError::InvalidPublicValues(
                "recursion public values are invalid",
            ));
        }

        // The `vk_root` is the expected `vk_root`.
        if public_values.vk_root != self.recursion_vks.root() {
            return Err(MachineVerifierError::InvalidPublicValues("vk_root mismatch"));
        }

        // If `vk_verification` is on, check the `vk` is within the expected list of `vk`'s.
        // This `vk_verification` must be only turned off for testing purposes.
        if self.vk_verification() && !self.recursion_vks.verify(vk_merkle_proof, shrink_vk) {
            return Err(MachineVerifierError::InvalidVerificationKey);
        }

        // `is_complete` should be 1. This ensures that the proof is fully reduced.
        if public_values.is_complete != SP1Field::one() {
            return Err(MachineVerifierError::InvalidPublicValues("is_complete is not 1"));
        }

        // Verify that the proof is for the sp1 vkey we are expecting.
        let vkey_hash = vk.hash_koalabear();
        if public_values.sp1_vk_digest != vkey_hash {
            return Err(MachineVerifierError::InvalidPublicValues("sp1 vk hash mismatch"));
        }

        Ok(())
    }

    /// Verify a wrap bn254 proof.
    pub fn verify_wrap_bn254(
        &self,
        proof: &SP1WrapProof<SP1OuterGlobalContext, SP1PcsProofOuter>,
        vk: &SP1VerifyingKey,
    ) -> Result<(), MachineVerifierConfigError<SP1OuterGlobalContext, SP1OuterPcs>> {
        let wrap_vk = &self.wrap_vk;
        if proof.vk != *wrap_vk {
            return Err(MachineVerifierError::InvalidVerificationKey);
        }

        let SP1WrapProof { vk: _, proof } = proof;

        let mut challenger = self.wrap.challenger();
        wrap_vk.observe_into(&mut challenger);

        // Check the public values length.
        if proof.public_values.len() != PROOF_MAX_NUM_PVS {
            return Err(MachineVerifierError::InvalidPublicValues("invalid public values length"));
        }

        // Verify the shard proof.
        self.wrap
            .verify_shard(wrap_vk, proof, &mut challenger)
            .map_err(MachineVerifierError::InvalidShardProof)?;

        // Validate public values.
        let public_values: &RootPublicValues<_> = proof.public_values.as_slice().borrow();
        if !is_root_public_values_valid(public_values) {
            return Err(MachineVerifierError::InvalidPublicValues(
                "root public values are invalid",
            ));
        }

        // The `vk_root` is the expected `vk_root`.
        if *public_values.vk_root() != self.recursion_vks.root() {
            return Err(MachineVerifierError::InvalidPublicValues("vk_root mismatch"));
        }

        // Verify that the proof is for the sp1 vkey we are expecting.
        let vkey_hash = vk.hash_koalabear();
        if *public_values.sp1_vk_digest() != vkey_hash {
            return Err(MachineVerifierError::InvalidPublicValues("sp1 vk hash mismatch"));
        }

        Ok(())
    }

    /// Verifies a PLONK proof using the circuit artifacts in the build directory.
    pub fn verify_plonk_bn254(&self, proof: &PlonkBn254Proof, vk: &SP1VerifyingKey) -> Result<()> {
        let prover = PlonkBn254Prover::new();

        let vkey_hash = parse_bn254_public_input(&proof.public_inputs[0])?;
        let committed_values_digest = parse_bn254_public_input(&proof.public_inputs[1])?;
        let exit_code = parse_bn254_public_input(&proof.public_inputs[2])?;
        let vk_root = parse_bn254_public_input(&proof.public_inputs[3])?;
        let proof_nonce = parse_bn254_public_input(&proof.public_inputs[4])?;
        let expected_vk_root = koalabears_to_bn254(&self.recursion_vks.root());

        if vk_root != expected_vk_root.as_canonical_biguint() {
            return Err(anyhow!("vk_root mismatch"));
        }

        if vk.hash_bn254().as_canonical_biguint() != vkey_hash {
            return Err(PlonkVerificationError::InvalidVerificationKey.into());
        }

        // The encoded_proof contains: exit_code(32) + vk_root(32) + proof_nonce(32) + proof
        // We need to extract just the proof bytes (starting at offset 96)
        let encoded_bytes = hex::decode(&proof.encoded_proof)?;
        if encoded_bytes.len() < 96 {
            return Err(anyhow!(
                "Invalid encoded_proof length: {} (expected at least 96)",
                encoded_bytes.len()
            ));
        }

        // Convert BigUint to padded 32-byte big-endian array
        let to_bytes32 = |v: &BigUint| -> [u8; 32] {
            let mut padded = [0u8; 32];
            let bytes = v.to_bytes_be();
            let start = 32usize.saturating_sub(bytes.len());
            padded[start..].copy_from_slice(&bytes[..bytes.len().min(32)]);
            padded
        };

        // Cross-validate that the metadata embedded in encoded_proof matches public_inputs.
        if encoded_bytes[0..32] != to_bytes32(&exit_code)
            || encoded_bytes[32..64] != to_bytes32(&vk_root)
            || encoded_bytes[64..96] != to_bytes32(&proof_nonce)
        {
            return Err(anyhow!("encoded_proof metadata does not match public inputs"));
        }

        // Verify the proof with the corresponding public inputs.
        if use_development_mode() {
            let build_dir = plonk_bn254_artifacts_dev_dir(&self.wrap_vk)?;
            if !build_dir.exists() {
                return Err(anyhow!("{:?} development plonk build dir does not exist", build_dir));
            }
            prover.verify(
                proof,
                &vkey_hash,
                &committed_values_digest,
                &exit_code,
                &vk_root,
                &proof_nonce,
                &build_dir,
            )?;
        } else {
            let proof_bytes = &encoded_bytes[96..];
            let public_inputs = [
                to_bytes32(&vkey_hash),
                to_bytes32(&committed_values_digest),
                to_bytes32(&exit_code),
                to_bytes32(&vk_root),
                to_bytes32(&proof_nonce),
            ];
            PlonkVerifier::verify_gnark_proof(proof_bytes, &public_inputs, &PLONK_VK_BYTES)?
        }

        Ok(())
    }

    /// Verifies a Groth16 proof using the circuit artifacts in the build directory.
    pub fn verify_groth16_bn254(
        &self,
        proof: &Groth16Bn254Proof,
        vk: &SP1VerifyingKey,
    ) -> Result<()> {
        let prover = Groth16Bn254Prover::new();

        let vkey_hash = parse_bn254_public_input(&proof.public_inputs[0])?;
        let committed_values_digest = parse_bn254_public_input(&proof.public_inputs[1])?;
        let exit_code = parse_bn254_public_input(&proof.public_inputs[2])?;
        let vk_root = parse_bn254_public_input(&proof.public_inputs[3])?;
        let proof_nonce = parse_bn254_public_input(&proof.public_inputs[4])?;
        let expected_vk_root = koalabears_to_bn254(&self.recursion_vks.root());

        if vk_root != expected_vk_root.as_canonical_biguint() {
            return Err(anyhow!("vk_root mismatch"));
        }

        if vk.hash_bn254().as_canonical_biguint() != vkey_hash {
            return Err(Groth16VerificationError::InvalidVerificationKey.into());
        }

        // The encoded_proof contains: exit_code(32) + vk_root(32) + proof_nonce(32) + proof(256)
        // We need to extract just the proof bytes (starting at offset 96)
        let encoded_bytes = hex::decode(&proof.encoded_proof)?;
        if encoded_bytes.len() < 96 + 256 {
            return Err(anyhow!(
                "Invalid encoded_proof length: {} (expected at least {})",
                encoded_bytes.len(),
                96 + 256
            ));
        }

        // Convert BigUint to padded 32-byte big-endian array
        let to_bytes32 = |v: &BigUint| -> [u8; 32] {
            let mut padded = [0u8; 32];
            let bytes = v.to_bytes_be();
            let start = 32usize.saturating_sub(bytes.len());
            padded[start..].copy_from_slice(&bytes[..bytes.len().min(32)]);
            padded
        };

        // Cross-validate that the metadata embedded in encoded_proof matches public_inputs.
        if encoded_bytes[0..32] != to_bytes32(&exit_code)
            || encoded_bytes[32..64] != to_bytes32(&vk_root)
            || encoded_bytes[64..96] != to_bytes32(&proof_nonce)
        {
            return Err(anyhow!("encoded_proof metadata does not match public inputs"));
        }

        // Verify the proof with the corresponding public inputs.
        if use_development_mode() {
            let build_dir = groth16_bn254_artifacts_dev_dir(&self.wrap_vk)?;
            if !build_dir.exists() {
                return Err(anyhow!(
                    "{:?} development groth16 build dir does not exist",
                    build_dir
                ));
            }
            prover.verify(
                proof,
                &vkey_hash,
                &committed_values_digest,
                &exit_code,
                &vk_root,
                &proof_nonce,
                &build_dir,
            )?;
        } else {
            let proof_bytes = &encoded_bytes[96..];
            let public_inputs = [
                to_bytes32(&vkey_hash),
                to_bytes32(&committed_values_digest),
                to_bytes32(&exit_code),
                to_bytes32(&vk_root),
                to_bytes32(&proof_nonce),
            ];
            Groth16Verifier::verify_gnark_proof(proof_bytes, &public_inputs, &GROTH16_VK_BYTES)?
        }

        Ok(())
    }
}

/// Verify the chunk-level structure of a core proof, given the public values.
fn check_core_chunk_structure(pvs: &[&SP1CorePublicValues<SP1Field>]) -> Result<(), &'static str> {
    let one_timestamp = [SP1Field::zero(), SP1Field::zero(), SP1Field::zero(), SP1Field::one()];

    let mut expected_chunk_idx = 0u32;
    let mut prev_chunk_merkle_root: Option<[SP1Field; POSEIDON_NUM_WORDS]> = None;
    let mut i = 0;
    while i < pvs.len() {
        let chunk_idx = pvs[i].trace_chunk_idx;
        if chunk_idx != SP1Field::from_canonical_u32(expected_chunk_idx) {
            return Err("trace_chunk_idx is not dense (chunks must be contiguous starting from 0)");
        }

        // Gather this chunk's contiguous run of shards.
        let start = i;
        while i < pvs.len() && pvs[i].trace_chunk_idx == chunk_idx {
            i += 1;
        }
        let chunk = &pvs[start..i];

        // Every shard in the chunk agrees on the chunk's shard counts.
        let num_merkle = chunk[0].num_merkle_shard;
        let num_execution = chunk[0].num_execution_shard;
        if chunk
            .iter()
            .any(|pv| pv.num_merkle_shard != num_merkle || pv.num_execution_shard != num_execution)
        {
            return Err("num_merkle_shard / num_execution_shard differ within a trace chunk");
        }
        let num_merkle = num_merkle.as_canonical_u32() as usize;
        let num_execution = num_execution.as_canonical_u32() as usize;
        if num_merkle == 0 {
            return Err("a trace chunk must have at least one merkle shard");
        }
        if num_execution == 0 {
            return Err("a trace chunk must have at least one execution shard");
        }
        if chunk.len() != num_merkle + num_execution {
            return Err(
                "trace chunk shard count does not equal num_merkle_shard + num_execution_shard",
            );
        }

        // Kind + index layout.
        for (k, pv) in chunk.iter().enumerate() {
            if k < num_merkle && pv.is_execution_shard != SP1Field::zero() {
                return Err("shard_kind does not match the canonical merkle-then-execution layout");
            }
            if k >= num_merkle && pv.is_execution_shard != SP1Field::one() {
                return Err("shard_kind does not match the canonical merkle-then-execution layout");
            }
            if pv.shard_index != SP1Field::from_canonical_usize(k) {
                return Err(
                    "shard_index does not match the canonical order within the trace chunk",
                );
            }
        }

        // Merkle roots: shared within the chunk, chained across chunks.
        let prev_root = chunk[0].prev_merkle_root;
        let cur_root = chunk[0].merkle_root;
        if chunk.iter().any(|pv| pv.prev_merkle_root != prev_root || pv.merkle_root != cur_root) {
            return Err("prev_merkle_root / merkle_root differ within a trace chunk");
        }
        if let Some(previous_root) = prev_chunk_merkle_root {
            if prev_root != previous_root {
                return Err(
                    "prev_merkle_root does not chain from the previous chunk's merkle_root",
                );
            }
        }
        prev_chunk_merkle_root = Some(cur_root);

        // Timestamps chain within the chunk and reset at the boundary.
        let mut prev_timestamp = one_timestamp;
        for pv in chunk {
            if pv.initial_timestamp != prev_timestamp {
                return Err("initial_timestamp does not chain within the trace chunk");
            }
            if pv.is_execution_shard != SP1Field::zero()
                && pv.initial_timestamp == pv.last_timestamp
            {
                return Err("timestamp should change on an execution shard");
            }
            if pv.is_execution_shard != SP1Field::one() && pv.initial_timestamp != pv.last_timestamp
            {
                return Err("timestamp should not change on a non-execution shard");
            }
            prev_timestamp = pv.last_timestamp;
        }

        expected_chunk_idx += 1;
    }

    Ok(())
}

/// Verify every core shard under its trace chunk's shared global challenge, and check that each
/// chunk's per-shard global cumulative sums cancel to zero.
pub(crate) fn verify_core_shards(
    core: &MachineVerifier<SP1GlobalContext, CoreSC>,
    vk: &MachineVerifyingKey<SP1GlobalContext>,
    proof: &SP1CoreProofData,
) -> Result<(), MachineVerifierConfigError<SP1GlobalContext, SP1InnerPcs>> {
    // Group the shard indices by trace chunk.
    let mut chunks: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    for (i, shard_proof) in proof.0.iter().enumerate() {
        let pv: &PublicValues<[_; 4], [_; 3], [_; 4], _> =
            shard_proof.public_values.as_slice().borrow();
        chunks.entry(pv.trace_chunk_idx.as_canonical_u32()).or_default().push(i);
    }

    // Within each chunk, order the shards.
    for indices in chunks.values_mut() {
        indices.sort_by_key(|&i| {
            let pv: &PublicValues<[_; 4], [_; 3], [_; 4], _> =
                proof.0[i].public_values.as_slice().borrow();
            proof_sort_key(
                pv.trace_chunk_idx.as_canonical_u32(),
                1 - pv.is_execution_shard.as_canonical_u32(),
                pv.shard_index.as_canonical_u32(),
            )
        });
    }

    for (chunk_idx, indices) in &chunks {
        // The chunk's ordered global commitments; verify folds them into the challenge.
        let commitments = indices
            .iter()
            .map(|&i| {
                proof.0[i].global_commitment.ok_or(MachineVerifierError::InvalidPublicValues(
                    "core shard is missing its global commitment",
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut global_cumulative_sum = SP1ExtensionField::zero();
        for &i in indices {
            let shard_proof = &proof.0[i];
            let span = tracing::debug_span!("verify shard proof", chunk = chunk_idx, i).entered();
            let mut challenger = core.challenger();
            vk.observe_into(&mut challenger);
            core.shard_verifier()
                .verify_shard_with_global_commitments(
                    vk,
                    shard_proof,
                    Some(&commitments),
                    &mut challenger,
                )
                .map_err(MachineVerifierError::InvalidShardProof)?;
            global_cumulative_sum += shard_proof.global_cumulative_sum.ok_or(
                MachineVerifierError::InvalidPublicValues(
                    "core shard is missing its global cumulative sum",
                ),
            )?;
            span.exit();
        }

        // The global cumulative sum should be zero across a trace chunk.
        if global_cumulative_sum != SP1ExtensionField::zero() {
            return Err(MachineVerifierError::GlobalCumulativeSumNonZero);
        }
    }

    Ok(())
}

/// In SP1, a proof's public values can either be hashed with SHA2 or Blake3. In SP1 V4, there is no
/// metadata attached to the proof about which hasher function was used for public values hashing.
/// Instead, when verifying the proof, the public values are hashed with SHA2 and Blake3, and
/// if either matches the `expected_public_values_hash`, the verification is successful.
///
/// The security for this verification in SP1 V4 derives from the fact that both SHA2 and Blake3 are
/// designed to be collision resistant. It is computationally infeasible to find an input i1 for
/// SHA256 and an input i2 for Blake3 that the same hash value. Doing so would require breaking both
/// algorithms simultaneously.
pub fn verify_public_values(
    public_values: &SP1PublicValues,
    expected_public_values_hash: BigUint,
) -> Result<()> {
    // First, check if the public values are hashed with SHA256. If that fails, attempt hashing with
    // Blake3. If neither match, return an error.
    let sha256_public_values_hash = public_values.hash_bn254();
    if sha256_public_values_hash != expected_public_values_hash {
        let blake3_public_values_hash = public_values.hash_bn254_with_fn(blake3_hash);
        if blake3_public_values_hash != expected_public_values_hash {
            return Err(Groth16VerificationError::InvalidPublicValues.into());
        }
    }

    Ok(())
}

/// Parse a BN254 public input string as a BigUint and verify it fits within 32 bytes.
fn parse_bn254_public_input(s: &str) -> Result<BigUint> {
    let value = BigUint::from_str(s)?;
    if value.to_bytes_be().len() > 32 {
        return Err(anyhow!("public input exceeds 32 bytes: {}", s));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_vk_bytes_deserialize() {
        let _vk: MachineVerifyingKey<SP1OuterGlobalContext> =
            bincode::deserialize(WRAP_VK_BYTES).expect("WRAP_VK_BYTES failed to deserialize");
    }

    /// Build one trace chunk's public values in canonical order: a single merkle shard (timestamps
    /// `(1, 1)`) followed by `num_exec` execution shards whose timestamps chain `1 → 2 → … `. Only
    /// the fields `check_core_chunk_structure` reads are populated.
    fn chunk_shards(
        chunk_idx: u32,
        prev_root: [u32; 8],
        cur_root: [u32; 8],
        num_exec: u32,
    ) -> Vec<PublicValues<u32, u64, u64, u32>> {
        let mut out = vec![PublicValues::<u32, u64, u64, u32> {
            trace_chunk_idx: chunk_idx,
            shard_index: 0,
            num_merkle_shard: 1,
            num_execution_shard: num_exec,
            prev_merkle_root: prev_root,
            merkle_root: cur_root,
            is_execution_shard: 0,
            initial_timestamp: 1,
            last_timestamp: 1,
            ..Default::default()
        }];

        for shard_index in 0..num_exec {
            let timestamp = 1 + u64::from(shard_index);
            out.push(PublicValues::<u32, u64, u64, u32> {
                trace_chunk_idx: chunk_idx,
                shard_index: shard_index + 1,
                num_merkle_shard: 1,
                num_execution_shard: num_exec,
                prev_merkle_root: prev_root,
                merkle_root: cur_root,
                is_execution_shard: 1,
                initial_timestamp: timestamp,
                last_timestamp: timestamp + 1,
                ..Default::default()
            });
        }
        out
    }

    fn to_field_pvs(
        pvs: &[PublicValues<u32, u64, u64, u32>],
    ) -> Vec<SP1CorePublicValues<SP1Field>> {
        pvs.iter().map(|pv| (*pv).into()).collect()
    }

    fn accepts(pvs: &[PublicValues<u32, u64, u64, u32>]) -> Result<(), &'static str> {
        let field_pvs = to_field_pvs(pvs);
        check_core_chunk_structure(&field_pvs.iter().collect::<Vec<_>>())
    }

    /// `check_core_chunk_structure` accepts a canonically-ordered two-chunk proof and rejects each
    /// structural corruption: a non-dense chunk index, disagreeing per-chunk counts, a broken
    /// kind/index layout, a broken within-chunk timestamp chain, a broken cross-chunk root chain,
    /// and a second `is_first_merkle_shard` in one chunk.
    #[test]
    fn check_core_chunk_structure_accepts_and_rejects() {
        let base = || {
            let mut pvs = chunk_shards(0, [0; 8], [7; 8], 2);
            pvs.extend(chunk_shards(1, [7; 8], [9; 8], 1));
            pvs
        };

        accepts(&base()).expect("a canonical two-chunk proof has valid structure");

        // Non-dense trace chunk index (gap 0 -> 2).
        {
            let mut pvs = chunk_shards(0, [0; 8], [7; 8], 2);
            pvs.extend(chunk_shards(2, [7; 8], [9; 8], 1));
            assert!(accepts(&pvs).is_err(), "a chunk-index gap must be rejected");
        }

        // A shard disagreeing on the chunk's execution-shard count.
        {
            let mut pvs = base();
            pvs[1].num_execution_shard = 3;
            assert!(accepts(&pvs).is_err(), "disagreeing per-chunk counts must be rejected");
        }

        // An out-of-order execution `shard_index`.
        {
            let mut pvs = base();
            pvs[2].shard_index = 5;
            assert!(accepts(&pvs).is_err(), "an out-of-order shard_index must be rejected");
        }

        // A broken within-chunk timestamp chain (second exec shard does not resume).
        {
            let mut pvs = base();
            pvs[2].initial_timestamp = 9;
            assert!(
                accepts(&pvs).is_err(),
                "a broken within-chunk timestamp chain must be rejected"
            );
        }

        // A broken cross-chunk root chain (chunk 1's prev_root != chunk 0's cur_root).
        {
            let mut pvs = chunk_shards(0, [0; 8], [7; 8], 2);
            pvs.extend(chunk_shards(1, [8; 8], [9; 8], 1));
            assert!(accepts(&pvs).is_err(), "a broken cross-chunk root chain must be rejected");
        }

        // A chunk that resets timestamps across the boundary is fine (each chunk starts at 1).
        accepts(&base())
            .expect("timestamps reset per chunk, so the second chunk starting at 1 is ok");
    }

    /// `check_core_chunk_structure` accepts the public values of a real, multi-chunk execution
    /// (a small chunk threshold splits fibonacci into several chunks), exercising the merkle-shard
    /// population (pc / timestamps / roots / counts) end to end without proving.
    #[test]
    fn check_core_chunk_structure_accepts_real_multi_chunk_records() {
        use sp1_core_executor::{Program, SP1CoreOpts, HALT_PC};
        use sp1_core_machine::{io::SP1Stdin, utils::generate_records};
        use std::sync::Arc;

        let program = Arc::new(Program::from(&test_artifacts::FIBONACCI_ELF).unwrap());
        let pc_start_abs = program.pc_start_abs;
        let opts = SP1CoreOpts { minimal_trace_chunk_threshold: 1 << 9, ..Default::default() };
        let (mut records, _) =
            generate_records::<SP1Field>(program, SP1Stdin::new(), opts, [0; 4]).unwrap();

        let max_chunk = records.iter().map(|r| r.trace_chunk_idx).max().unwrap();
        assert!(max_chunk >= 1, "expected a multi-chunk execution, got {} chunk(s)", max_chunk + 1);

        // Canonical proof order: by trace chunk, merkle shards first, then by shard index.
        records.sort_by_key(|r| proof_sort_key(r.trace_chunk_idx, r.shard_kind, r.shard_index));
        let field_pvs: Vec<SP1CorePublicValues<SP1Field>> =
            records.iter().map(|r| r.public_values.into()).collect();

        check_core_chunk_structure(&field_pvs.iter().collect::<Vec<_>>())
            .expect("real multi-chunk records have valid chunk structure");

        // The merkle pass-through makes the linear pc chain survive across chunk boundaries: every
        // shard's `next_pc` is the following shard's `pc_start`, anchored at the program start and
        // ending at `HALT_PC`. Previously the merkle shard's pc was zero, breaking this at the head
        // of every chunk — the original blocker for the top-level `verify`.
        let pc_limbs = |pc: u64| {
            [
                SP1Field::from_canonical_u16((pc & 0xFFFF) as u16),
                SP1Field::from_canonical_u16(((pc >> 16) & 0xFFFF) as u16),
                SP1Field::from_canonical_u16(((pc >> 32) & 0xFFFF) as u16),
            ]
        };
        let mut prev_next_pc = pc_limbs(pc_start_abs);
        for pv in &field_pvs {
            assert_eq!(pv.pc_start, prev_next_pc, "pc chain broken across the sorted shards");
            prev_next_pc = pv.next_pc;
        }
        assert_eq!(prev_next_pc, pc_limbs(HALT_PC), "execution should end at HALT_PC");
    }

    /// `vk.initial_memory_root` equals the first chunk's `prev_merkle_root`, cross-checking the two
    /// paths to the root (vk: `Program::initial_memory_root`, prover: `LeafState::from_memory_image`).
    #[tokio::test(flavor = "multi_thread")]
    async fn vk_initial_memory_root_matches_first_chunk_prev_root() {
        use sp1_core_executor::{Program, SP1CoreOpts};
        use sp1_core_machine::{io::SP1Stdin, utils::generate_records};
        use sp1_hypercube::prover::{
            AirProver, CpuShardProver, ProverSemaphore, SP1InnerPcsProver,
        };
        use std::sync::Arc;

        let permit = ProverSemaphore::new(1);
        let core_verifier = CpuSP1ProverComponents::core_verifier(RiscvAir::machine());
        let prover: CpuShardProver<
            SP1GlobalContext,
            SP1InnerPcs,
            SP1InnerPcsProver,
            RiscvAir<SP1Field>,
        > = CpuShardProver::new(core_verifier.shard_verifier().clone());

        let program = Arc::new(Program::from(&test_artifacts::FIBONACCI_ELF).unwrap());
        // Small threshold → several chunks.
        let opts = SP1CoreOpts { minimal_trace_chunk_threshold: 1 << 9, ..Default::default() };
        let (mut records, _) =
            generate_records::<SP1Field>(program.clone(), SP1Stdin::new(), opts, [0; 4]).unwrap();
        records.sort_by_key(|r| proof_sort_key(r.trace_chunk_idx, r.shard_kind, r.shard_index));

        let (_, vk) = prover.setup(program.clone(), permit.clone()).await;

        let first_pv: SP1CorePublicValues<SP1Field> = records[0].public_values.into();
        assert_eq!(
            first_pv.prev_merkle_root, vk.initial_memory_root,
            "vk.initial_memory_root must equal the first chunk's prev_merkle_root"
        );
        // Non-empty initial memory ⇒ non-default root.
        let empty_root: [SP1Field; POSEIDON_NUM_WORDS] =
            sp1_core_executor::merkle::memory_image_root(&Default::default())
                .map(|e| SP1Field::from_canonical_u32(e.as_canonical_u32()));
        assert_ne!(
            vk.initial_memory_root, empty_root,
            "fibonacci has non-empty initial memory, so its root is not the empty-tree root"
        );
    }

    /// A single trace chunk's shards, proven under the chunk's shared commitments (folded into one
    /// Merkle root), verify through the per-chunk pass and their global cumulative sums cancel. The
    /// three tampering modes — a wrong global commitment, a dropped shard, and a chunk whose global
    /// sums do not cancel — are each rejected.
    #[tokio::test(flavor = "multi_thread")]
    async fn core_proof_verifies_per_chunk_with_real_seam() {
        use sp1_core_executor::{Program, SP1CoreOpts, SHARD_KIND_EXECUTION};
        use sp1_core_machine::{io::SP1Stdin, utils::generate_records};
        use sp1_hypercube::prover::{
            AirProver, CpuShardProver, ProverSemaphore, SP1InnerPcsProver,
        };
        use std::sync::Arc;

        let permit = ProverSemaphore::new(1);

        let core_verifier = CpuSP1ProverComponents::core_verifier(RiscvAir::machine());
        let prover: CpuShardProver<
            SP1GlobalContext,
            SP1InnerPcs,
            SP1InnerPcsProver,
            RiscvAir<SP1Field>,
        > = CpuShardProver::new(core_verifier.shard_verifier().clone());

        let program = Arc::new(Program::from(&test_artifacts::FIBONACCI_ELF).unwrap());

        // A large chunk threshold keeps the whole execution in one Fiat-Shamir context.
        let opts = SP1CoreOpts { minimal_trace_chunk_threshold: 1 << 26, ..Default::default() };
        let (mut records, _) =
            generate_records::<SP1Field>(program.clone(), SP1Stdin::new(), opts, [0; 4]).unwrap();

        assert!(records.iter().all(|r| r.trace_chunk_idx == 0), "expected a single trace chunk");
        assert!(records.len() >= 2, "expected at least a merkle and an execution shard");

        // Canonical order: merkle shards before execution shards, then by shard index. The
        // chunk-ordering metadata in the public values is populated by `generate_records`.
        records.sort_by_key(|r| proof_sort_key(r.trace_chunk_idx, r.shard_kind, r.shard_index));

        let (pk, vk) = prover.setup(program.clone(), permit.clone()).await;
        let pk = unsafe { pk.into_inner() };

        // Harvest each shard's (challenge-independent) global commitment in canonical order by
        // proving it standalone (no chunk commitments) and reading the committed digest.
        let mut commitments = Vec::new();
        for record in &records {
            let (proof, _) =
                prover.prove_shard_with_pk(pk.clone(), record.clone(), permit.clone()).await;
            commitments
                .push(proof.global_commitment.expect("a core shard has a global commitment"));
        }

        // Prove every shard under the chunk's shared commitments (stamped onto each record).
        let mut shard_proofs = Vec::new();
        for record in &records {
            let mut record = record.clone();
            record.set_global_commitments::<SP1GlobalContext>(&commitments);
            let (proof, _) = prover.prove_shard_with_pk(pk.clone(), record, permit.clone()).await;
            shard_proofs.push(proof);
        }
        let proof = SP1CoreProofData(shard_proofs);

        verify_core_shards(&core_verifier, &vk, &proof)
            .expect("a single-chunk core proof verifies under the chunk's commitments");

        // Tampering one global commitment should make the verification fail.
        {
            let mut tampered = proof.clone();
            let commitment = tampered.0[0].global_commitment.as_mut().unwrap();
            commitment[0] += SP1Field::one();
            assert!(
                verify_core_shards(&core_verifier, &vk, &tampered).is_err(),
                "a tampered global commitment must fail verification"
            );
        }

        // Dropping a shard also makes the verification fail.
        {
            let mut dropped = proof.clone();
            dropped.0.pop();
            assert!(
                verify_core_shards(&core_verifier, &vk, &dropped).is_err(),
                "dropping a shard from the chunk must fail verification"
            );
        }

        // A single execution shard, proven as its own chunk, verifies on its own, but its global
        // interactions (received by the absent merkle shard) leave a non-zero cumulative sum.
        {
            let exec_idx = records
                .iter()
                .position(|r| r.shard_kind == SHARD_KIND_EXECUTION)
                .expect("a chunk has an execution shard");
            let mut solo_record = records[exec_idx].clone();
            solo_record.set_global_commitments::<SP1GlobalContext>(&[commitments[exec_idx]]);
            let (solo_proof, _) =
                prover.prove_shard_with_pk(pk.clone(), solo_record, permit.clone()).await;
            assert_ne!(
                solo_proof.global_cumulative_sum,
                Some(SP1ExtensionField::zero()),
                "a lone execution shard has a non-zero global cumulative sum"
            );
            let solo = SP1CoreProofData(vec![solo_proof]);
            assert!(
                matches!(
                    verify_core_shards(&core_verifier, &vk, &solo),
                    Err(MachineVerifierError::GlobalCumulativeSumNonZero)
                ),
                "a chunk whose global cumulative sums do not cancel must be rejected"
            );
        }
    }

    /// The worker's two-phase flow end to end: `generate_global_commitment` per shard yields the
    /// chunk's ordered commitments, then `prove_shard` proves each shard under them.
    /// The execution-shard commitment is committed from a `shard_data`-only seed — mirroring the
    /// worker, which commits the global trace *before* tracing the chunk — while the merkle-shard
    /// commitment comes from its record. The test pins the invariant that each shard's in-proof
    /// global commitment equals the digest pre-committed for it, and that the resulting proof
    /// verifies through the per-chunk pass with sums cancelling.
    #[tokio::test(flavor = "multi_thread")]
    async fn worker_core_proof_matches_precommitted_digests_and_verifies() {
        use crate::worker::{order_commitments, AirProverWorker, CommitKind};
        use sp1_core_executor::{
            ExecutionRecord, Program, SP1CoreOpts, SHARD_KIND_EXECUTION, SHARD_KIND_MERKLE,
        };
        use sp1_core_machine::{io::SP1Stdin, utils::generate_records};
        use sp1_hypercube::prover::{CpuShardProver, ProverSemaphore, SP1InnerPcsProver};
        use std::sync::Arc;

        let permit = ProverSemaphore::new(1);

        let core_verifier = CpuSP1ProverComponents::core_verifier(RiscvAir::machine());
        let prover: CpuShardProver<
            SP1GlobalContext,
            SP1InnerPcs,
            SP1InnerPcsProver,
            RiscvAir<SP1Field>,
        > = CpuShardProver::new(core_verifier.shard_verifier().clone());

        let program = Arc::new(Program::from(&test_artifacts::FIBONACCI_ELF).unwrap());

        // A large chunk threshold keeps the whole execution in one Fiat-Shamir context.
        let opts = SP1CoreOpts { minimal_trace_chunk_threshold: 1 << 26, ..Default::default() };
        let (mut records, _) =
            generate_records::<SP1Field>(program.clone(), SP1Stdin::new(), opts, [0; 4]).unwrap();

        assert!(records.iter().all(|r| r.trace_chunk_idx == 0), "expected a single trace chunk");
        assert!(records.len() >= 2, "expected at least a merkle and an execution shard");

        // Canonical order: merkle shards before execution shards, then by shard index.
        records.sort_by_key(|r| proof_sort_key(r.trace_chunk_idx, r.shard_kind, r.shard_index));

        // Phase 1 — global commitments, derived exactly as the worker derives them: an execution
        // shard commits from a `shard_data`-only seed (the worker commits before the chunk is
        // traced), a merkle shard from its record.
        let mut collected = Vec::new();
        for record in &records {
            let digest = if record.shard_kind == SHARD_KIND_EXECUTION {
                let seed = ExecutionRecord::from_shard_data(
                    program.clone(),
                    record.public_values.proof_nonce,
                    record.global_dependencies_opt,
                    record.shard_data.clone().expect("an execution shard carries shard data"),
                );
                prover.generate_global_commitment(&seed, permit.clone()).await
            } else {
                prover.generate_global_commitment(record, permit.clone()).await
            };
            let kind = if record.shard_kind == SHARD_KIND_MERKLE {
                CommitKind::Merkle
            } else {
                CommitKind::Core
            };
            collected.push((kind, record.shard_index, digest));
        }
        let commitments = order_commitments(collected);

        // Phase 2 — prove every shard under the chunk's shared commitments.
        let mut shard_proofs = Vec::new();
        for record in &records {
            let proof =
                prover.prove_shard(program.clone(), record, &commitments, permit.clone()).await;
            shard_proofs.push(proof);
        }

        for (i, proof) in shard_proofs.iter().enumerate() {
            assert_eq!(
                proof.global_commitment.expect("a core shard has a global commitment"),
                commitments[i],
                "shard {i}: in-proof global commitment must match the pre-committed digest"
            );
        }

        // The worker-built proof verifies through the per-chunk seam, and its global cumulative
        // sums cancel.
        let (_, vk) = prover.setup(program.clone(), permit.clone()).await;
        let proof = SP1CoreProofData(shard_proofs);
        verify_core_shards(&core_verifier, &vk, &proof).expect(
            "a worker-built single-chunk core proof verifies under the chunk's commitments",
        );
    }
}
