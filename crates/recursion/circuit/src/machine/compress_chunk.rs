use std::{
    array,
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    mem::MaybeUninit,
};

use itertools::Itertools;
use slop_air::Air;
use slop_algebra::AbstractField;
use sp1_core_machine::riscv::MAX_LOG_NUMBER_OF_SHARDS;
use sp1_hypercube::{
    air::{MachineAir, POSEIDON_NUM_WORDS, PV_DIGEST_NUM_WORDS},
    DIGEST_SIZE,
};
use sp1_primitives::{SP1Field, SP1GlobalContext};
use sp1_recursion_compiler::ir::{Builder, Felt, IrIter};
use sp1_recursion_executor::{RecursionPublicValues, RECURSIVE_PROOF_NUM_PV_ELTS};

use crate::{
    challenger::CanObserveVariable,
    machine::{
        // assert_complete,
        assert_recursion_public_values_valid,
        recursion_public_values_digest,
        root_public_values_digest,
        InnerVal,
        PublicValuesOutputDigest,
        SP1CompressWithVKeyWitnessVariable,
        SP1MerkleProofVerifier,
        SP1ShapedWitnessVariable,
    },
    shard::RecursiveShardVerifier,
    zerocheck::RecursiveVerifierConstraintFolder,
    CircuitConfig, SP1FieldConfigVariable,
};

/// Within-chunk compress: folds a chunk's normalize leaves toward one chunk proof.
#[derive(Debug, Clone, Copy)]
pub struct SP1ChunkCompressVerifier<C, SC, A> {
    _phantom: PhantomData<(C, SC, A)>,
}

impl<C, SC, A> SP1ChunkCompressVerifier<C, SC, A>
where
    C: CircuitConfig<Bit = Felt<SP1Field>>,
    A: MachineAir<InnerVal> + for<'a> Air<RecursiveVerifierConstraintFolder<'a>>,
{
    pub fn verify(
        builder: &mut Builder<C>,
        machine: &RecursiveShardVerifier<SP1GlobalContext, A, C>,
        input: SP1CompressWithVKeyWitnessVariable<C, SP1GlobalContext>,
        value_assertions: bool,
        kind: PublicValuesOutputDigest,
    ) {
        // Verify vk-merkle membership.
        let values = input
            .compress_var
            .vks_and_proofs
            .iter()
            .map(|(vk, _)| vk.hash(builder))
            .collect::<Vec<_>>();
        let vk_root = input.merkle_var.root.map(|x| builder.eval(x));
        SP1MerkleProofVerifier::verify(builder, values, input.merkle_var, value_assertions);

        let SP1ShapedWitnessVariable { vks_and_proofs, is_complete } = input.compress_var;

        // Initialize the values for the aggregated public output.
        let mut reduce_public_values_stream: Vec<Felt<_>> = (0..RECURSIVE_PROOF_NUM_PV_ELTS)
            .map(|_| unsafe { MaybeUninit::zeroed().assume_init() })
            .collect();
        let compress_public_values: &mut RecursionPublicValues<_> =
            reduce_public_values_stream.as_mut_slice().borrow_mut();

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
        let mut commit_syscall: Felt<_> = unsafe { MaybeUninit::zeroed().assume_init() };
        let mut commit_deferred_syscall: Felt<_> = unsafe { MaybeUninit::zeroed().assume_init() };
        let mut contains_first_shard: Felt<_> = builder.eval(SP1Field::zero());
        let mut num_included_shard: Felt<_> = builder.eval(SP1Field::zero());
        let mut shard_index: Felt<_> = builder.eval(SP1Field::zero());
        let mut prev_chunk_index: Felt<_> = builder.eval(SP1Field::zero());
        let mut last_chunk_index: Felt<_> = builder.eval(SP1Field::zero());
        let mut initial_memory_root: [Felt<_>; POSEIDON_NUM_WORDS] =
            array::from_fn(|_| builder.uninit());
        let mut last_memory_root: [Felt<_>; POSEIDON_NUM_WORDS] =
            array::from_fn(|_| builder.uninit());
        let mut num_merkle_shard: Felt<_> = builder.eval(SP1Field::zero());
        let mut num_execution_shard: Felt<_> = builder.eval(SP1Field::zero());
        let mut reconstruct_global_challenge: [Felt<_>; 16] =
            array::from_fn(|_| unsafe { MaybeUninit::zeroed().assume_init() });
        let mut global_commitments_hash: [Felt<_>; 8] =
            array::from_fn(|_| unsafe { MaybeUninit::zeroed().assume_init() });
        let mut proof_nonce: [Felt<_>; 4] =
            array::from_fn(|_| unsafe { MaybeUninit::zeroed().assume_init() });
        let mut global_cumulative_sum: [Felt<_>; 4] =
            array::from_fn(|_| builder.eval(SP1Field::zero()));

        // Verify each child proof.
        vks_and_proofs.iter().ir_par_map_collect::<Vec<_>, _, _>(
            builder,
            |builder, (vk, shard_proof)| {
                let mut challenger = SP1GlobalContext::challenger_variable(builder);
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
                let zero: Felt<_> = builder.eval(SP1Field::zero());
                for _ in 0..4 {
                    challenger.observe(builder, zero);
                }
                machine.verify_shard(builder, vk, shard_proof, &mut challenger, None);
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

            // Accumulate the global cumulative sum.
            for (idx, sum) in global_cumulative_sum.iter_mut().enumerate() {
                *sum = builder.eval(*sum + current_public_values.global_cumulative_sum[idx]);
            }

            if i == 0 {
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

                // Initialize the chunk index.
                prev_chunk_index = current_public_values.prev_chunk_index;
                last_chunk_index = current_public_values.last_chunk_index;

                // Initiallize start pc.
                compress_public_values.pc_start = current_public_values.pc_start;
                pc = current_public_values.pc_start;

                // Initialize timestamp.
                compress_public_values.initial_timestamp = current_public_values.initial_timestamp;
                current_timestamp = current_public_values.initial_timestamp;

                // Initialize the memory merkle root.
                initial_memory_root = current_public_values.initial_memory_root;
                last_memory_root = current_public_values.last_memory_root;

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

                // Initialize the shard index.
                compress_public_values.prev_shard_index = current_public_values.prev_shard_index;
                shard_index = current_public_values.prev_shard_index;

                // Initialize the number of merkle, execution shards.
                num_merkle_shard = current_public_values.num_merkle_shard;
                num_execution_shard = current_public_values.num_execution_shard;

                // Initialize the global challenge state.
                compress_public_values.start_reconstruct_global_challenge =
                    current_public_values.start_reconstruct_global_challenge;
                reconstruct_global_challenge =
                    current_public_values.start_reconstruct_global_challenge;
                global_commitments_hash = current_public_values.global_commitments_hash;
            }

            // Assert that the current values match the accumulated values and update them.
            // Assert that the sp1_vk digest is always the same.
            for (digest, current) in
                sp1_vk_digest.iter().zip_eq(current_public_values.sp1_vk_digest)
            {
                builder.assert_felt_eq(*digest, current);
            }

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

            // Assert that the `prev_chunk_index` and `last_chunk_index` is equal.
            builder.assert_felt_eq(prev_chunk_index, current_public_values.prev_chunk_index);
            builder.assert_felt_eq(last_chunk_index, current_public_values.last_chunk_index);

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

            // Assert that the initial memory root is the same.
            for (digest, current) in
                initial_memory_root.iter().zip_eq(current_public_values.initial_memory_root)
            {
                builder.assert_felt_eq(*digest, current);
            }

            // Assert that the last memory root is the same.
            for (digest, current) in
                last_memory_root.iter().zip_eq(current_public_values.last_memory_root)
            {
                builder.assert_felt_eq(*digest, current);
            }

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

            // Assert that the `prev_shard_index` is equal to the current one, then update.
            builder.assert_felt_eq(shard_index, current_public_values.prev_shard_index);
            shard_index = current_public_values.last_shard_index;

            // Assert that the `num_merkle_shard` and `num_execution_shard` is identical.
            builder.assert_felt_eq(num_merkle_shard, current_public_values.num_merkle_shard);
            builder.assert_felt_eq(num_execution_shard, current_public_values.num_execution_shard);

            // Assert that the start reconstruct global challenge is correct.
            for (digest, current_digest) in reconstruct_global_challenge
                .iter()
                .zip_eq(current_public_values.start_reconstruct_global_challenge.iter())
            {
                builder.assert_felt_eq(*digest, *current_digest);
            }
            reconstruct_global_challenge = current_public_values.end_reconstruct_global_challenge;

            // Assert that the `global_commitments_hash` is identical.
            for (digest, current) in
                global_commitments_hash.iter().zip_eq(current_public_values.global_commitments_hash)
            {
                builder.assert_felt_eq(*digest, current);
            }

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

        // Update the global values from the last accumulated values.
        // Set the `committed_value_digest`.
        compress_public_values.committed_value_digest = committed_value_digest;
        // Set the `deferred_proofs_digest`.
        compress_public_values.deferred_proofs_digest = deferred_proofs_digest;
        // Set next_pc to be the last pc.
        compress_public_values.next_pc = pc;
        // Set the timestamp to be the last timestamp.
        compress_public_values.last_timestamp = current_timestamp;
        // Set the start reconstruct deferred digest to be the last reconstruct deferred digest.
        compress_public_values.end_reconstruct_deferred_digest = reconstruct_deferred_digest;
        // Set the deferred proof index to be the last deferred proof index.
        compress_public_values.deferred_proof = deferred_proof_index;
        // Set the chunk indices.
        compress_public_values.prev_chunk_index = prev_chunk_index;
        compress_public_values.last_chunk_index = last_chunk_index;
        // Set sp1_vk digest to the one from the proof values.
        compress_public_values.sp1_vk_digest = sp1_vk_digest;
        // Reflect the vk root.
        compress_public_values.vk_root = vk_root;
        // Set the memory root.
        compress_public_values.initial_memory_root = initial_memory_root;
        compress_public_values.last_memory_root = last_memory_root;
        // Set the shard index.
        compress_public_values.last_shard_index = shard_index;
        // Set the number of merkle and execution shards.
        compress_public_values.num_merkle_shard = num_merkle_shard;
        compress_public_values.num_execution_shard = num_execution_shard;
        // Set the global challenge related public values.
        compress_public_values.end_reconstruct_global_challenge = reconstruct_global_challenge;
        compress_public_values.global_commitments_hash = global_commitments_hash;
        // Set the global cumulative sum.
        compress_public_values.global_cumulative_sum = global_cumulative_sum;
        // Assign the `contains_first_shard` flag.
        compress_public_values.contains_first_shard = contains_first_shard;
        // Assign the `num_included_shard` value.
        compress_public_values.num_included_shard = num_included_shard;
        // The witness flag marks chunk completeness; a within-chunk proof is never is_complete.
        compress_public_values.is_complete = builder.eval(SP1Field::zero());
        compress_public_values.is_chunk_complete = is_complete;
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
        // assert_complete(builder, compress_public_values, is_complete);

        SP1GlobalContext::commit_recursion_public_values(builder, *compress_public_values);
    }
}
