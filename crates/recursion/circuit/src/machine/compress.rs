use std::{
    array,
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    mem::MaybeUninit,
};

use itertools::Itertools;

use slop_air::Air;

use slop_algebra::{AbstractField, PrimeField32};
use slop_challenger::IopCtx;

use serde::{Deserialize, Serialize};
use sp1_core_machine::riscv::MAX_LOG_NUMBER_OF_SHARDS;
use sp1_recursion_compiler::ir::{Builder, Felt, IrIter};

use sp1_primitives::{SP1Field, SP1GlobalContext};
use sp1_recursion_executor::{RecursionPublicValues, RECURSIVE_PROOF_NUM_PV_ELTS};

use sp1_hypercube::{
    air::{MachineAir, ShardRange, POSEIDON_NUM_WORDS, PV_DIGEST_NUM_WORDS},
    MachineVerifyingKey, ShardProof, DIGEST_SIZE,
};

use crate::{
    challenger::CanObserveVariable,
    machine::{
        assert_complete, assert_recursion_public_values_valid, recursion_public_values_digest,
        root_public_values_digest,
    },
    shard::{MachineVerifyingKeyVariable, RecursiveShardVerifier, ShardProofVariable},
    zerocheck::RecursiveVerifierConstraintFolder,
    CircuitConfig, SP1FieldConfigVariable,
};

use sp1_recursion_compiler::circuit::CircuitV2Builder;

use super::InnerVal;
/// A program to verify a batch of recursive proofs and aggregate their public values.
#[derive(Debug, Clone, Copy)]
pub struct SP1CompressVerifier<C, SC, A> {
    _phantom: PhantomData<(C, SC, A)>,
}

pub enum PublicValuesOutputDigest {
    Reduce,
    Root,
}

/// Witness layout for the compress stage verifier.
#[allow(clippy::type_complexity)]
pub struct SP1ShapedWitnessVariable<C: CircuitConfig, GC: SP1FieldConfigVariable<C>> {
    /// The shard proofs to verify.
    pub vks_and_proofs: Vec<(MachineVerifyingKeyVariable<C, GC>, ShardProofVariable<C, GC>)>,
    pub is_complete: Felt<SP1Field>,
}

pub type VkAndProof<GC, Proof> = (MachineVerifyingKey<GC>, ShardProof<GC, Proof>);

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "ShardProof<GC,Proof>: Serialize"))]
#[serde(bound(deserialize = "ShardProof<GC,Proof>: Deserialize<'de>"))]
/// An input layout for the shard proofs that have been normalized to a standard shape.
pub struct SP1ShapedWitnessValues<GC: IopCtx, Proof> {
    pub vks_and_proofs: Vec<VkAndProof<GC, Proof>>,
    pub is_complete: bool,
}

impl<GC: IopCtx, Proof> SP1ShapedWitnessValues<GC, Proof> {
    pub fn range(&self) -> ShardRange
    where
        GC::F: PrimeField32,
    {
        let start_pv: &RecursionPublicValues<GC::F> =
            self.vks_and_proofs[0].1.public_values.as_slice().borrow();
        let end_pv: &RecursionPublicValues<GC::F> =
            self.vks_and_proofs[self.vks_and_proofs.len() - 1].1.public_values.as_slice().borrow();

        let start = start_pv.range().start();
        let end = end_pv.range().end();

        (start..end).into()
    }
}

impl<C, SC, A> SP1CompressVerifier<C, SC, A>
where
    C: CircuitConfig<Bit = Felt<SP1Field>>,
    A: MachineAir<InnerVal> + for<'a> Air<RecursiveVerifierConstraintFolder<'a>>,
{
    /// Verify a batch of recursive proofs and aggregate their public values.
    ///
    /// The compression verifier can aggregate proofs of different kinds:
    /// - Core proofs: proofs which are recursive proof of a batch of SP1 shard proofs. The
    ///   implementation in this function assumes a fixed recursive verifier specified by
    ///   `recursive_vk`.
    /// - Deferred proofs: proofs which are recursive proof of a batch of deferred proofs. The
    ///   implementation in this function assumes a fixed deferred verification program specified by
    ///   `deferred_vk`.
    /// - Compress proofs: these are proofs which refer to a prove of this program. The key for it
    ///   is part of public values will be propagated across all levels of recursion and will be
    ///   checked against itself as in [sp1_prover::Prover] or as in [super::SP1RootVerifier].
    pub fn verify(
        builder: &mut Builder<C>,
        machine: &RecursiveShardVerifier<SP1GlobalContext, A, C>,
        input: SP1ShapedWitnessVariable<C, SP1GlobalContext>,
        vk_root: [Felt<SP1Field>; DIGEST_SIZE],
        kind: PublicValuesOutputDigest,
    ) {
        // Read input.
        let SP1ShapedWitnessVariable { vks_and_proofs, is_complete } = input;

        // Initialize the values for the aggregated public output.
        let mut reduce_public_values_stream: Vec<Felt<_>> = (0..RECURSIVE_PROOF_NUM_PV_ELTS)
            .map(|_| unsafe { MaybeUninit::zeroed().assume_init() })
            .collect();
        let compress_public_values: &mut RecursionPublicValues<_> =
            reduce_public_values_stream.as_mut_slice().borrow_mut();

        // Make sure there is at least one proof.
        assert!(!vks_and_proofs.is_empty());

        // Initialize the consistency check variables.
        let mut sp1_vk_digest: [Felt<_>; DIGEST_SIZE] =
            array::from_fn(|_| unsafe { MaybeUninit::zeroed().assume_init() });
        let mut pc: [Felt<_>; 3] =
            array::from_fn(|_| unsafe { MaybeUninit::zeroed().assume_init() });
        let mut current_exit_code: Felt<_> = unsafe { MaybeUninit::zeroed().assume_init() };
        let mut current_timestamp: [Felt<_>; 4] = array::from_fn(|_| builder.uninit());

        let mut committed_value_digest: [[Felt<_>; 4]; PV_DIGEST_NUM_WORDS] =
            array::from_fn(|_| array::from_fn(|_| unsafe { MaybeUninit::zeroed().assume_init() }));
        let mut deferred_proofs_digest: [Felt<_>; POSEIDON_NUM_WORDS] =
            array::from_fn(|_| unsafe { MaybeUninit::zeroed().assume_init() });
        let mut deferred_proof_index: Felt<_> = unsafe { MaybeUninit::zeroed().assume_init() };
        let mut reconstruct_deferred_digest: [Felt<_>; POSEIDON_NUM_WORDS] =
            core::array::from_fn(|_| unsafe { MaybeUninit::zeroed().assume_init() });
        let mut global_cumulative_sums = Vec::new();
        let mut init_addr: [Felt<_>; 3] =
            array::from_fn(|_| unsafe { MaybeUninit::zeroed().assume_init() });
        let mut finalize_addr: [Felt<_>; 3] =
            array::from_fn(|_| unsafe { MaybeUninit::zeroed().assume_init() });
        let mut init_page_idx: [Felt<_>; 3] =
            array::from_fn(|_| unsafe { MaybeUninit::zeroed().assume_init() });
        let mut finalize_page_idx: [Felt<_>; 3] =
            array::from_fn(|_| unsafe { MaybeUninit::zeroed().assume_init() });
        let mut commit_syscall: Felt<_> = unsafe { MaybeUninit::zeroed().assume_init() };
        let mut commit_deferred_syscall: Felt<_> = unsafe { MaybeUninit::zeroed().assume_init() };
        let mut contains_first_shard: Felt<_> = builder.eval(SP1Field::zero());
        let mut num_included_shard: Felt<_> = builder.eval(SP1Field::zero());
        let mut proof_nonce: [Felt<_>; 4] =
            array::from_fn(|_| unsafe { MaybeUninit::zeroed().assume_init() });

        // Verify the shard proofs.
        // Verification of proofs can be done in parallel but the aggregation/consistency checks
        // must be done sequentially.
        vks_and_proofs.iter().ir_par_map_collect::<Vec<_>, _, _>(
            builder,
            |builder, (vk, shard_proof)| {
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
                machine.verify_shard(builder, vk, shard_proof, &mut challenger);
            },
        );

        // Check consistency and aggregate public values.
        for (i, (_, shard_proof)) in vks_and_proofs.into_iter().enumerate() {
            // Get the current public values.
            let current_public_values: &RecursionPublicValues<Felt<SP1Field>> =
                shard_proof.public_values.as_slice().borrow();
            // Assert that the public values are valid.
            assert_recursion_public_values_valid::<C, SP1GlobalContext>(
                builder,
                current_public_values,
            );
            // Assert that the vk root is the same as the witnessed one.
            for (expected, actual) in vk_root.iter().zip_eq(current_public_values.vk_root.iter()) {
                builder.assert_felt_eq(*expected, *actual);
            }

            // Verify that there are less than `(1 << MAX_LOG_NUMBER_OF_SHARDS)` included shards.
            C::range_check_felt(
                builder,
                current_public_values.num_included_shard,
                MAX_LOG_NUMBER_OF_SHARDS,
            );

            // Verify that `contains_first_shard` is boolean.
            builder.assert_felt_eq(
                current_public_values.contains_first_shard
                    * (current_public_values.contains_first_shard - SP1Field::one()),
                SP1Field::zero(),
            );

            // Accumulate the number of included shards.
            num_included_shard =
                builder.eval(num_included_shard + current_public_values.num_included_shard);

            // Accumulate the `contains_first_shard` flag.
            contains_first_shard =
                builder.eval(contains_first_shard + current_public_values.contains_first_shard);

            // Add the global cumulative sums to the vector.
            global_cumulative_sums.push(current_public_values.global_cumulative_sum);

            if i == 0 {
                // Initialize global and accumulated values.

                // Assign the committed values and deferred proof digests.
                compress_public_values.prev_committed_value_digest =
                    current_public_values.prev_committed_value_digest;
                committed_value_digest = current_public_values.prev_committed_value_digest;

                compress_public_values.prev_deferred_proofs_digest =
                    current_public_values.prev_deferred_proofs_digest;
                deferred_proofs_digest = current_public_values.prev_deferred_proofs_digest;

                // Initialize the deferred proof index.
                compress_public_values.prev_deferred_proof =
                    current_public_values.prev_deferred_proof;
                deferred_proof_index = current_public_values.prev_deferred_proof;

                // Initiallize start pc.
                compress_public_values.pc_start = current_public_values.pc_start;
                pc = current_public_values.pc_start;

                // Initialize timestamp.
                compress_public_values.initial_timestamp = current_public_values.initial_timestamp;
                current_timestamp = current_public_values.initial_timestamp;

                // Initialize the MemoryInitialize address.
                compress_public_values.previous_init_addr =
                    current_public_values.previous_init_addr;
                init_addr = current_public_values.previous_init_addr;

                // Initialize the MemoryFinalize address.
                compress_public_values.previous_finalize_addr =
                    current_public_values.previous_finalize_addr;
                finalize_addr = current_public_values.previous_finalize_addr;

                // Initialize the PageProtInit address.
                compress_public_values.previous_init_page_idx =
                    current_public_values.previous_init_page_idx;
                init_page_idx = current_public_values.previous_init_page_idx;

                // Initialize the PageProtFinalize address.
                compress_public_values.previous_finalize_page_idx =
                    current_public_values.previous_finalize_page_idx;
                finalize_page_idx = current_public_values.previous_finalize_page_idx;

                // Initialize the start of deferred digests.
                compress_public_values.start_reconstruct_deferred_digest =
                    current_public_values.start_reconstruct_deferred_digest;
                reconstruct_deferred_digest =
                    current_public_values.start_reconstruct_deferred_digest;

                // Initialize exit code.
                compress_public_values.prev_exit_code = current_public_values.prev_exit_code;
                current_exit_code = current_public_values.prev_exit_code;

                // Initialize `commit_syscall`.
                compress_public_values.prev_commit_syscall =
                    current_public_values.prev_commit_syscall;
                commit_syscall = current_public_values.prev_commit_syscall;

                // Initialize `commit_deferred_syscall`.
                compress_public_values.prev_commit_deferred_syscall =
                    current_public_values.prev_commit_deferred_syscall;
                commit_deferred_syscall = current_public_values.prev_commit_deferred_syscall;

                // Initialize the sp1_vk digest
                compress_public_values.sp1_vk_digest = current_public_values.sp1_vk_digest;
                sp1_vk_digest = current_public_values.sp1_vk_digest;

                // Initialize the proof nonce.
                compress_public_values.proof_nonce = current_public_values.proof_nonce;
                proof_nonce = current_public_values.proof_nonce;
            }

            // Assert that the current values match the accumulated values and update them.

            // Assert that the `prev_committed_value_digest` is equal to current one, then update.
            for (word, current_word) in committed_value_digest
                .iter()
                .zip_eq(current_public_values.prev_committed_value_digest.iter())
            {
                for (limb, current_limb) in word.iter().zip_eq(current_word.iter()) {
                    builder.assert_felt_eq(*limb, *current_limb);
                }
            }
            committed_value_digest = current_public_values.committed_value_digest;

            // Assert that the `prev_deferred_proofs_digest` is equal to current one, then update.
            for (limb, current_limb) in deferred_proofs_digest
                .iter()
                .zip_eq(current_public_values.prev_deferred_proofs_digest.iter())
            {
                builder.assert_felt_eq(*limb, *current_limb);
            }
            deferred_proofs_digest = current_public_values.deferred_proofs_digest;

            // Assert that the `prev_deferred_proof` is equal to the current one, then update.
            builder.assert_felt_eq(deferred_proof_index, current_public_values.prev_deferred_proof);
            deferred_proof_index = current_public_values.deferred_proof;

            // Assert that the start pc is equal to the current pc, then update.
            for (limb, current_limb) in pc.iter().zip_eq(current_public_values.pc_start.iter()) {
                builder.assert_felt_eq(*limb, *current_limb);
            }
            pc = current_public_values.next_pc;

            // Verify that the timestamp is equal to the current one, then update.
            for (limb, current_limb) in
                current_timestamp.iter().zip_eq(current_public_values.initial_timestamp.iter())
            {
                builder.assert_felt_eq(*limb, *current_limb);
            }
            current_timestamp = current_public_values.last_timestamp;

            // Verify that the init address is equal to the current one, then update.
            for (limb, current_limb) in
                init_addr.iter().zip_eq(current_public_values.previous_init_addr.iter())
            {
                builder.assert_felt_eq(*limb, *current_limb);
            }
            init_addr = current_public_values.last_init_addr;

            // Verify that the finalize address is equal to the current one, then update.
            for (limb, current_limb) in
                finalize_addr.iter().zip_eq(current_public_values.previous_finalize_addr.iter())
            {
                builder.assert_felt_eq(*limb, *current_limb);
            }
            finalize_addr = current_public_values.last_finalize_addr;

            // Verify that the init page index is equal to the current one, then update.
            for (limb, current_limb) in
                init_page_idx.iter().zip_eq(current_public_values.previous_init_page_idx.iter())
            {
                builder.assert_felt_eq(*limb, *current_limb);
            }
            init_page_idx = current_public_values.last_init_page_idx;

            // Verify that the finalize page index is equal to the current one, then update.
            for (limb, current_limb) in finalize_page_idx
                .iter()
                .zip_eq(current_public_values.previous_finalize_page_idx.iter())
            {
                builder.assert_felt_eq(*limb, *current_limb);
            }
            finalize_page_idx = current_public_values.last_finalize_page_idx;

            // Assert that the start deferred digest is equal to the current one, then update.
            for (digest, current_digest) in reconstruct_deferred_digest
                .iter()
                .zip_eq(current_public_values.start_reconstruct_deferred_digest.iter())
            {
                builder.assert_felt_eq(*digest, *current_digest);
            }
            reconstruct_deferred_digest = current_public_values.end_reconstruct_deferred_digest;

            // Assert that the `prev_exit_code` is equal to the current one, then update.
            builder.assert_felt_eq(current_exit_code, current_public_values.prev_exit_code);
            current_exit_code = current_public_values.exit_code;

            // Assert that the `prev_commit_syscall` is equal to the current one, then update.
            builder.assert_felt_eq(commit_syscall, current_public_values.prev_commit_syscall);
            commit_syscall = current_public_values.commit_syscall;

            // Assert that `prev_commit_deferred_syscall` is equal to the current one, then update.
            builder.assert_felt_eq(
                commit_deferred_syscall,
                current_public_values.prev_commit_deferred_syscall,
            );
            commit_deferred_syscall = current_public_values.commit_deferred_syscall;

            // Assert that the sp1_vk digest is always the same.
            for (digest, current) in
                sp1_vk_digest.iter().zip_eq(current_public_values.sp1_vk_digest)
            {
                builder.assert_felt_eq(*digest, current);
            }

            // Assert that the `proof_nonce` is equal to the current one, then update.
            for (limb, current_limb) in
                proof_nonce.iter().zip_eq(current_public_values.proof_nonce.iter())
            {
                builder.assert_felt_eq(*limb, *current_limb);
            }
        }

        // Range check the accumulated number of included shards.
        C::range_check_felt(builder, num_included_shard, MAX_LOG_NUMBER_OF_SHARDS);

        // Check that the `contains_first_shard` flag is boolean.
        builder.assert_felt_eq(
            contains_first_shard * (contains_first_shard - SP1Field::one()),
            SP1Field::zero(),
        );

        // Sum all the global cumulative sum of the proofs.
        let global_cumulative_sum = builder.sum_digest_v2(global_cumulative_sums);

        // Update the global values from the last accumulated values.
        // Set the `committed_value_digest`.
        compress_public_values.committed_value_digest = committed_value_digest;
        // Set the `deferred_proofs_digest`.
        compress_public_values.deferred_proofs_digest = deferred_proofs_digest;
        // Set next_pc to be the last pc.
        compress_public_values.next_pc = pc;
        // Set the timestamp to be the last timestamp.
        compress_public_values.last_timestamp = current_timestamp;
        // Set the MemoryInitialize address to be the last MemoryInitialize address.
        compress_public_values.last_init_addr = init_addr;
        // Set the MemoryFinalize address to be the last MemoryFinalize address.
        compress_public_values.last_finalize_addr = finalize_addr;
        // Set the PageProtInit address to be the last PageProtInit address.
        compress_public_values.last_init_page_idx = init_page_idx;
        // Set the PageProtFinalize address to be the last PageProtFinalize address.
        compress_public_values.last_finalize_page_idx = finalize_page_idx;
        // Set the start reconstruct deferred digest to be the last reconstruct deferred digest.
        compress_public_values.end_reconstruct_deferred_digest = reconstruct_deferred_digest;
        // Set the deferred proof index to be the last deferred proof index.
        compress_public_values.deferred_proof = deferred_proof_index;
        // Set sp1_vk digest to the one from the proof values.
        compress_public_values.sp1_vk_digest = sp1_vk_digest;
        // Reflect the vk root.
        compress_public_values.vk_root = vk_root;
        // Assign the cumulative sum.
        compress_public_values.global_cumulative_sum = global_cumulative_sum;
        // Assign the `contains_first_shard` flag.
        compress_public_values.contains_first_shard = contains_first_shard;
        // Assign the `num_included_shard` value.
        compress_public_values.num_included_shard = num_included_shard;
        // Assign the `is_complete` flag.
        compress_public_values.is_complete = is_complete;
        // Set the exit code.
        compress_public_values.exit_code = current_exit_code;
        // Set the `commit_syscall` flag.
        compress_public_values.commit_syscall = commit_syscall;
        // Set the `commit_deferred_syscall` flag.
        compress_public_values.commit_deferred_syscall = commit_deferred_syscall;
        compress_public_values.proof_nonce = proof_nonce;
        // Set the digest according to the previous values.
        compress_public_values.digest = match kind {
            PublicValuesOutputDigest::Reduce => {
                recursion_public_values_digest::<C, SP1GlobalContext>(
                    builder,
                    compress_public_values,
                )
            }
            PublicValuesOutputDigest::Root => {
                root_public_values_digest::<C, SP1GlobalContext>(builder, compress_public_values)
            }
        };

        // If the proof is complete, make completeness assertions.
        assert_complete(builder, compress_public_values, is_complete);

        SP1GlobalContext::commit_recursion_public_values(builder, *compress_public_values);
    }
}
