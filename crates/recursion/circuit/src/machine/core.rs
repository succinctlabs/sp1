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

use sp1_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Config, Felt},
};

use sp1_recursion_executor::{RecursionPublicValues, DIGEST_SIZE, RECURSIVE_PROOF_NUM_PV_ELTS};

use crate::{
    challenger::CanObserveVariable,
    machine::{assert_complete, recursion_public_values_digest},
    shard::{MachineVerifyingKeyVariable, RecursiveShardVerifier, ShardProofVariable},
    zerocheck::RecursiveVerifierConstraintFolder,
    CircuitConfig, SP1FieldConfigVariable,
};

pub struct SP1RecursionWitnessVariable<C: CircuitConfig, SC: SP1FieldConfigVariable<C>> {
    pub vk: MachineVerifyingKeyVariable<C, SC>,
    pub shard_proofs: Vec<ShardProofVariable<C, SC>>,
    pub reconstruct_deferred_digest: [Felt<SP1Field>; DIGEST_SIZE],
    pub num_deferred_proofs: Felt<SP1Field>,
    pub is_complete: Felt<SP1Field>,
    pub vk_root: [Felt<SP1Field>; DIGEST_SIZE],
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "ShardProof<GC,Proof>: Serialize"))]
#[serde(bound(deserialize = "ShardProof<GC,Proof>: Deserialize<'de>"))]
/// A struct to contain the inputs to the `normalize` program.
pub struct SP1NormalizeWitnessValues<GC: IopCtx, Proof> {
    pub vk: MachineVerifyingKey<GC>,
    pub shard_proofs: Vec<ShardProof<GC, Proof>>,
    pub is_complete: bool,
    pub vk_root: [GC::F; DIGEST_SIZE],
    pub reconstruct_deferred_digest: [GC::F; 8],
    pub num_deferred_proofs: GC::F,
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
            is_complete,
            vk_root,
            reconstruct_deferred_digest,
            num_deferred_proofs,
        } = input;

        // Assert that the number of proofs is one.
        assert!(shard_proofs.len() == 1);
        let shard_proof = &shard_proofs[0];

        // Initialize the cumulative sum.
        let mut global_cumulative_sums = Vec::new();

        // Get the public values.
        let public_values: &PublicValues<[Felt<_>; 4], [Felt<_>; 3], [Felt<_>; 4], Felt<_>> =
            shard_proof.public_values.as_slice().borrow();

        // If it's the first shard, then the `pc_start` should be vk.pc_start.
        for (pc, vk_pc) in public_values.pc_start.iter().zip_eq(vk.pc_start.iter()) {
            builder.assert_felt_eq(
                public_values.is_first_execution_shard * (*pc - *vk_pc),
                SP1Field::zero(),
            );
        }

        // If it's the first shard, we add the vk's `initial_global_cumulative_sum` to the
        // digest. If it's not the first shard, we add the zero digest to the digest.
        global_cumulative_sums.push(builder.select_global_cumulative_sum(
            public_values.is_first_execution_shard,
            vk.initial_global_cumulative_sum,
        ));

        // Prepare a challenger.
        let mut challenger = SP1GlobalContext::challenger_variable(builder);

        // Observe the vk and start pc.
        challenger.observe(builder, vk.preprocessed_commit);
        challenger.observe_slice(builder, vk.pc_start);
        challenger.observe_slice(builder, vk.initial_global_cumulative_sum.0.x.0);
        challenger.observe_slice(builder, vk.initial_global_cumulative_sum.0.y.0);
        challenger.observe(builder, vk.untrusted_config.enable_untrusted_programs);
        #[cfg(feature = "mprotect")]
        {
            challenger.observe(builder, vk.untrusted_config.enable_trap_handler);
            challenger.observe_slice(builder, vk.untrusted_config.trap_context);
            challenger.observe_slice(builder, vk.untrusted_config.untrusted_memory);
        }
        // Observe the padding.
        let zero: Felt<_> = builder.eval(SP1Field::zero());
        for _ in 0..6 {
            challenger.observe(builder, zero);
        }

        // Verify the shard proof.
        tracing::debug_span!("verify shard")
            .in_scope(|| machine.verify_shard(builder, &vk, shard_proof, &mut challenger));

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

        // We add the global cumulative sum of the shard.
        global_cumulative_sums.push(public_values.global_cumulative_sum);

        // We sum the digests in `global_cumulative_sums` to get the overall global cumulative sum.
        let global_cumulative_sum = builder.sum_digest_v2(global_cumulative_sums);

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
            recursion_public_values.pc_start = public_values.pc_start;
            recursion_public_values.next_pc = public_values.next_pc;
            recursion_public_values.initial_timestamp = public_values.initial_timestamp;
            recursion_public_values.last_timestamp = public_values.last_timestamp;
            recursion_public_values.previous_init_addr = public_values.previous_init_addr;
            recursion_public_values.last_init_addr = public_values.last_init_addr;
            recursion_public_values.previous_finalize_addr = public_values.previous_finalize_addr;
            recursion_public_values.last_finalize_addr = public_values.last_finalize_addr;
            recursion_public_values.previous_init_page_idx = public_values.previous_init_page_idx;
            recursion_public_values.last_init_page_idx = public_values.last_init_page_idx;
            recursion_public_values.previous_finalize_page_idx =
                public_values.previous_finalize_page_idx;
            recursion_public_values.last_finalize_page_idx = public_values.last_finalize_page_idx;
            recursion_public_values.start_reconstruct_deferred_digest = reconstruct_deferred_digest;
            recursion_public_values.end_reconstruct_deferred_digest = reconstruct_deferred_digest;
            recursion_public_values.sp1_vk_digest = vk_digest;
            recursion_public_values.vk_root = vk_root;
            recursion_public_values.global_cumulative_sum = global_cumulative_sum;
            recursion_public_values.contains_first_shard = public_values.is_first_execution_shard;
            recursion_public_values.num_included_shard = builder.eval(SP1Field::one());
            recursion_public_values.is_complete = is_complete;
            recursion_public_values.prev_exit_code = public_values.prev_exit_code;
            recursion_public_values.exit_code = public_values.exit_code;
            recursion_public_values.prev_commit_syscall = public_values.prev_commit_syscall;
            recursion_public_values.commit_syscall = public_values.commit_syscall;
            recursion_public_values.prev_commit_deferred_syscall =
                public_values.prev_commit_deferred_syscall;
            recursion_public_values.commit_deferred_syscall = public_values.commit_deferred_syscall;
            recursion_public_values.proof_nonce = public_values.proof_nonce;

            // Calculate the digest and set it in the public values.
            recursion_public_values.digest = recursion_public_values_digest::<C, SP1GlobalContext>(
                builder,
                recursion_public_values,
            );

            assert_complete(builder, recursion_public_values, is_complete);

            SP1GlobalContext::commit_recursion_public_values(builder, *recursion_public_values);
        }
    }
}
