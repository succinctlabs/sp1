use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
};

use itertools::Itertools;
use slop_air::Air;
use slop_algebra::{AbstractField, PrimeField32};
use slop_challenger::IopCtx;
use sp1_primitives::{SP1Field, SP1GlobalContext};

use serde::{Deserialize, Serialize};
use sp1_core_machine::riscv::RiscvAir;

use sp1_hypercube::air::{PublicValues, SP1CorePublicValues};

use sp1_hypercube::{air::ShardRange, MachineVerifyingKey, ShardProof};

use sp1_recursion_compiler::ir::{Builder, Config, Felt};

use sp1_recursion_executor::{
    RecursionPublicValues, DIGEST_SIZE, HASH_RATE, PERMUTATION_WIDTH, RECURSIVE_PROOF_NUM_PV_ELTS,
};

use crate::{
    challenger::CanObserveVariable,
    hash::Poseidon2SP1FieldHasherVariable,
    machine::recursion_public_values_digest,
    shard::{MachineVerifyingKeyVariable, RecursiveShardVerifier, ShardProofVariable},
    zerocheck::RecursiveVerifierConstraintFolder,
    CircuitConfig, SP1FieldConfigVariable,
};

pub struct SP1RecursionWitnessVariable<C: CircuitConfig, SC: SP1FieldConfigVariable<C>> {
    pub vk: MachineVerifyingKeyVariable<C, SC>,
    pub shard_proofs: Vec<ShardProofVariable<C, SC>>,
    pub reconstruct_deferred_digest: [Felt<SP1Field>; DIGEST_SIZE],
    pub num_deferred_proofs: Felt<SP1Field>,
    pub vk_root: [Felt<SP1Field>; DIGEST_SIZE],
    /// `H = hash_iter(commitments)` over the chunk's ordered global commitments; observing it
    /// re-derives the chunk's shared global challenge in-circuit.
    pub commitments_hash: [Felt<SP1Field>; DIGEST_SIZE],
    /// Running Poseidon2 state before this shard folds its global commitment into the chunk's
    /// running commitments hash. `[0; PERMUTATION_WIDTH]` for the first shard in the chunk.
    pub prev_hasher_state: [Felt<SP1Field>; PERMUTATION_WIDTH],
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "ShardProof<GC,Proof>: Serialize"))]
#[serde(bound(deserialize = "ShardProof<GC,Proof>: Deserialize<'de>"))]
/// A struct to contain the inputs to the `normalize` program.
pub struct SP1NormalizeWitnessValues<GC: IopCtx, Proof> {
    pub vk: MachineVerifyingKey<GC>,
    pub shard_proofs: Vec<ShardProof<GC, Proof>>,
    pub vk_root: [GC::F; DIGEST_SIZE],
    pub reconstruct_deferred_digest: [GC::F; 8],
    pub num_deferred_proofs: GC::F,
    /// `H = hash_iter(commitments)` over the chunk's ordered global commitments. Populate from
    /// `chunk_ctx` as the precomputed hash, not the commitment list.
    pub commitments_hash: [GC::F; DIGEST_SIZE],
    /// Running Poseidon2 state before this shard folds its global commitment into the chunk's
    /// running commitments hash. `[0; PERMUTATION_WIDTH]` for the first shard in the chunk.
    pub prev_hasher_state: [GC::F; PERMUTATION_WIDTH],
}

impl<GC: IopCtx, Proof> SP1NormalizeWitnessValues<GC, Proof> {
    pub fn range(&self) -> ShardRange
    where
        GC::F: PrimeField32,
    {
        let start_pv: &SP1CorePublicValues<GC::F> =
            self.shard_proofs[0].public_values.as_slice().borrow();
        let end_pv: &SP1CorePublicValues<GC::F> =
            self.shard_proofs[self.shard_proofs.len() - 1].public_values.as_slice().borrow();

        let start = start_pv.range().start();
        let end = end_pv.range().end();

        let mut range: ShardRange = (start..end).into();
        let num_deferred_proofs = self.num_deferred_proofs.as_canonical_u32() as u64;
        range.deferred_proof_range = (num_deferred_proofs, num_deferred_proofs);
        range
    }
}

/// A program for recursively verifying a batch of SP1 proofs.
#[derive(Debug, Clone, Copy)]
pub struct SP1RecursiveVerifier<C: Config> {
    _phantom: PhantomData<C>,
}

impl<C> SP1RecursiveVerifier<C>
where
    C: CircuitConfig<Bit = Felt<SP1Field>>,
{
    /// Verify a batch of SP1 shard proofs and aggregate their public values.
    ///
    /// This program represents a first recursive step in the verification of an SP1 proof
    /// consisting of one or more shards. Each shard proof is verified and its public values are
    /// turned into the recursion public values, which will be aggregated in compress.
    ///
    /// # Constraints
    ///
    /// ## Verifying the core shard proofs.
    /// For each shard, the verifier asserts the correctness of the shard proof which is composed
    /// of verifying the polynomial commitment's proof for openings and verifying the constraints.
    ///
    /// ## Verifing the first shard constraints.
    /// The first shard has some additional constraints for initialization.
    pub fn verify(
        builder: &mut Builder<C>,
        machine: &RecursiveShardVerifier<SP1GlobalContext, RiscvAir<SP1Field>, C>,
        input: SP1RecursionWitnessVariable<C, SP1GlobalContext>,
    ) where
        RiscvAir<SP1Field>: for<'b> Air<RecursiveVerifierConstraintFolder<'b>>,
    {
        // Read input.
        let SP1RecursionWitnessVariable {
            vk,
            shard_proofs,
            vk_root,
            reconstruct_deferred_digest,
            num_deferred_proofs,
            commitments_hash,
            prev_hasher_state,
            ..
        } = input;

        // Assert that the number of proofs is one.
        assert!(shard_proofs.len() == 1);
        let shard_proof = &shard_proofs[0];

        // Get the public values.
        let public_values: &PublicValues<[Felt<_>; 4], [Felt<_>; 3], [Felt<_>; 4], Felt<_>> =
            shard_proof.public_values.as_slice().borrow();

        // If it's the first shard, then the `pc_start` should be vk.pc_start.
        for (pc, vk_pc) in public_values.pc_start.iter().zip_eq(vk.pc_start.iter()) {
            builder.assert_felt_eq(public_values.is_first_shard * (*pc - *vk_pc), SP1Field::zero());
        }

        // If it's the first shard, then the `prev_merkle_root` should be `vk.initial_memory_root`.
        for (memory_root, vk_initial_memory_root) in
            public_values.prev_merkle_root.iter().zip_eq(vk.initial_memory_root.iter())
        {
            builder.assert_felt_eq(
                public_values.is_first_shard * (*memory_root - *vk_initial_memory_root),
                SP1Field::zero(),
            );
        }

        let global_cumulative_sum =
            C::ext2felt(builder, shard_proof.global_cumulative_sum.unwrap());

        // Prepare a challenger.
        let mut challenger = SP1GlobalContext::challenger_variable(builder);

        // Observe the vk and start pc.
        challenger.observe(builder, vk.preprocessed_commit);
        challenger.observe_slice(builder, vk.pc_start);
        challenger.observe_slice(builder, vk.initial_memory_root);
        challenger.observe(builder, vk.untrusted_config.enable_untrusted_programs);
        #[cfg(feature = "mprotect")]
        {
            challenger.observe(builder, vk.untrusted_config.enable_trap_handler);
            challenger.observe_slice(builder, vk.untrusted_config.trap_context);
            challenger.observe_slice(builder, vk.untrusted_config.untrusted_memory);
        }
        // Observe the padding.
        let zero: Felt<_> = builder.eval(SP1Field::zero());
        for _ in 0..4 {
            challenger.observe(builder, zero);
        }

        // Verify the shard proof.
        tracing::debug_span!("verify shard").in_scope(|| {
            machine.verify_shard(builder, &vk, shard_proof, &mut challenger, Some(commitments_hash))
        });

        // Assert that the `is_untrusted_programs_enabled` is equal to the vkey one.
        builder.assert_felt_eq(
            public_values.is_untrusted_programs_enabled,
            vk.untrusted_config.enable_untrusted_programs,
        );

        #[cfg(feature = "mprotect")]
        {
            // Assert that the `trap_context` is equal to the vkey one.
            for (pv_addr, vk_addr) in
                (public_values.trap_context.iter()).zip_eq(vk.untrusted_config.trap_context.iter())
            {
                for idx in 0..3 {
                    builder.assert_felt_eq(pv_addr[idx], vk_addr[idx]);
                }
            }

            // Assert that the `untrusted_memory` is equal to the vkey one.
            for (pv_addr, vk_addr) in (public_values.untrusted_memory.iter())
                .zip_eq(vk.untrusted_config.untrusted_memory.iter())
            {
                for idx in 0..3 {
                    builder.assert_felt_eq(pv_addr[idx], vk_addr[idx]);
                }
            }

            // Assert that the `enable_trap_handler` is equal to the vkey one.
            builder.assert_felt_eq(
                public_values.enable_trap_handler,
                vk.untrusted_config.enable_trap_handler,
            );
        }

        // Running commitments hash.
        let global_commitment =
            shard_proof.global_commitment.expect("core shard has a global commitment");
        let mut running_state = prev_hasher_state;
        running_state[..HASH_RATE].copy_from_slice(&global_commitment);
        let next_hasher_state =
            <SP1GlobalContext as Poseidon2SP1FieldHasherVariable<C>>::poseidon2_permute(
                builder,
                running_state,
            );

        // Write all values to the public values struct and commit to them.
        {
            // Compute the vk digest.
            let vk_digest = vk.hash(builder);

            // Initialize the public values we will commit to.
            let zero: Felt<_> = builder.eval(SP1Field::zero());
            let mut recursion_public_values_stream = [zero; RECURSIVE_PROOF_NUM_PV_ELTS];
            let recursion_public_values: &mut RecursionPublicValues<_> =
                recursion_public_values_stream.as_mut_slice().borrow_mut();
            recursion_public_values.prev_committed_value_digest =
                public_values.prev_committed_value_digest;
            recursion_public_values.committed_value_digest = public_values.committed_value_digest;
            recursion_public_values.prev_deferred_proofs_digest =
                public_values.prev_deferred_proofs_digest;
            recursion_public_values.deferred_proofs_digest = public_values.deferred_proofs_digest;
            recursion_public_values.prev_deferred_proof = num_deferred_proofs;
            recursion_public_values.deferred_proof = num_deferred_proofs;
            recursion_public_values.prev_chunk_index = public_values.trace_chunk_idx;
            recursion_public_values.last_chunk_index =
                builder.eval(public_values.trace_chunk_idx + SP1Field::one());
            recursion_public_values.pc_start = public_values.pc_start;
            recursion_public_values.next_pc = public_values.next_pc;
            recursion_public_values.initial_timestamp = public_values.initial_timestamp;
            recursion_public_values.last_timestamp = public_values.last_timestamp;
            recursion_public_values.initial_memory_root = public_values.prev_merkle_root;
            recursion_public_values.last_memory_root = public_values.merkle_root;
            recursion_public_values.start_reconstruct_deferred_digest = reconstruct_deferred_digest;
            recursion_public_values.end_reconstruct_deferred_digest = reconstruct_deferred_digest;
            recursion_public_values.sp1_vk_digest = vk_digest;
            recursion_public_values.vk_root = vk_root;
            recursion_public_values.global_cumulative_sum = global_cumulative_sum;
            recursion_public_values.contains_first_shard = public_values.is_first_shard;
            recursion_public_values.num_included_shard = builder.eval(SP1Field::one());
            recursion_public_values.is_complete = builder.eval(SP1Field::zero());
            recursion_public_values.prev_exit_code = public_values.prev_exit_code;
            recursion_public_values.exit_code = public_values.exit_code;
            recursion_public_values.prev_commit_syscall = public_values.prev_commit_syscall;
            recursion_public_values.commit_syscall = public_values.commit_syscall;
            recursion_public_values.prev_commit_deferred_syscall =
                public_values.prev_commit_deferred_syscall;
            recursion_public_values.commit_deferred_syscall = public_values.commit_deferred_syscall;
            recursion_public_values.proof_nonce = public_values.proof_nonce;
            recursion_public_values.prev_shard_index = public_values.shard_index;
            recursion_public_values.last_shard_index =
                builder.eval(public_values.shard_index + SP1Field::one());
            recursion_public_values.num_merkle_shard = public_values.num_merkle_shard;
            recursion_public_values.num_execution_shard = public_values.num_execution_shard;
            recursion_public_values.start_reconstruct_global_challenge = prev_hasher_state;
            recursion_public_values.end_reconstruct_global_challenge = next_hasher_state;
            recursion_public_values.global_commitments_hash = commitments_hash;
            recursion_public_values.is_chunk_complete = builder.eval(SP1Field::zero());

            // Calculate the digest and set it in the public values.
            recursion_public_values.digest = recursion_public_values_digest::<C, SP1GlobalContext>(
                builder,
                recursion_public_values,
            );

            SP1GlobalContext::commit_recursion_public_values(builder, *recursion_public_values);
        }
    }
}
