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
use sp1_hypercube::air::{MachineAir, POSEIDON_NUM_WORDS};
use sp1_primitives::{SP1Field, SP1GlobalContext};
use sp1_recursion_compiler::ir::{Builder, Felt, IrIter};
use sp1_recursion_executor::{RecursionPublicValues, RECURSIVE_PROOF_NUM_PV_ELTS};

use crate::{
    challenger::CanObserveVariable,
    machine::{
        assert_chunk_complete, assert_common_child, assert_constant,
        assert_recursion_public_values_valid, carry_forward, init_common_boundary,
        recursion_public_values_digest, root_public_values_digest, InnerVal,
        PublicValuesOutputDigest, SP1CompressWithVKeyWitnessVariable, SP1MerkleProofVerifier,
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

        let mut current_timestamp: [Felt<_>; 4] = array::from_fn(|_| builder.uninit());
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
                init_common_boundary(compress_public_values, current_public_values);

                prev_chunk_index = current_public_values.prev_chunk_index;
                last_chunk_index = current_public_values.last_chunk_index;
                compress_public_values.initial_timestamp = current_public_values.initial_timestamp;
                current_timestamp = current_public_values.initial_timestamp;
                initial_memory_root = current_public_values.initial_memory_root;
                last_memory_root = current_public_values.last_memory_root;
                compress_public_values.prev_shard_index = current_public_values.prev_shard_index;
                shard_index = current_public_values.prev_shard_index;
                num_merkle_shard = current_public_values.num_merkle_shard;
                num_execution_shard = current_public_values.num_execution_shard;
                compress_public_values.start_reconstruct_global_challenge =
                    current_public_values.start_reconstruct_global_challenge;
                reconstruct_global_challenge =
                    current_public_values.start_reconstruct_global_challenge;
                global_commitments_hash = current_public_values.global_commitments_hash;
            }

            assert_common_child(builder, compress_public_values, current_public_values);

            // `prev_chunk_index`, `last_chunk_index` is constant across a chunk.
            assert_constant(builder, prev_chunk_index, current_public_values.prev_chunk_index);
            assert_constant(builder, last_chunk_index, current_public_values.last_chunk_index);
            // The merkle roots are constant across a chunk.
            assert_constant(
                builder,
                initial_memory_root,
                current_public_values.initial_memory_root,
            );
            assert_constant(builder, last_memory_root, current_public_values.last_memory_root);
            // The number of merkle shard and execution shard is constant across a chunk.
            assert_constant(builder, num_merkle_shard, current_public_values.num_merkle_shard);
            assert_constant(
                builder,
                num_execution_shard,
                current_public_values.num_execution_shard,
            );
            // The global commitments hash is constant across a chunk.
            assert_constant(
                builder,
                global_commitments_hash,
                current_public_values.global_commitments_hash,
            );
            // Timestamp, shard index, global challenge reconstruction propagates.
            carry_forward(
                builder,
                &mut current_timestamp,
                current_public_values.initial_timestamp,
                current_public_values.last_timestamp,
            );
            carry_forward(
                builder,
                &mut shard_index,
                current_public_values.prev_shard_index,
                current_public_values.last_shard_index,
            );
            carry_forward(
                builder,
                &mut reconstruct_global_challenge,
                current_public_values.start_reconstruct_global_challenge,
                current_public_values.end_reconstruct_global_challenge,
            );
        }

        // Range check the accumulated number of included shards.
        C::range_check_felt(builder, num_included_shard, MAX_LOG_NUMBER_OF_SHARDS);

        // Check that the `contains_first_shard` flag is boolean.
        builder.assert_felt_eq(
            contains_first_shard * (contains_first_shard - SP1Field::one()),
            SP1Field::zero(),
        );

        // Set the final public values.
        compress_public_values.last_timestamp = current_timestamp;
        compress_public_values.prev_chunk_index = prev_chunk_index;
        compress_public_values.last_chunk_index = last_chunk_index;
        compress_public_values.vk_root = vk_root;
        compress_public_values.initial_memory_root = initial_memory_root;
        compress_public_values.last_memory_root = last_memory_root;
        compress_public_values.last_shard_index = shard_index;
        compress_public_values.num_merkle_shard = num_merkle_shard;
        compress_public_values.num_execution_shard = num_execution_shard;
        compress_public_values.end_reconstruct_global_challenge = reconstruct_global_challenge;
        compress_public_values.global_commitments_hash = global_commitments_hash;
        compress_public_values.global_cumulative_sum = global_cumulative_sum;
        compress_public_values.contains_first_shard = contains_first_shard;
        compress_public_values.num_included_shard = num_included_shard;
        // A within-chunk proof is never complete; the witness flag marks chunk completeness.
        compress_public_values.is_complete = builder.eval(SP1Field::zero());
        compress_public_values.is_chunk_complete = is_complete;
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

        // Check if the chunk is complete.
        assert_chunk_complete(builder, compress_public_values, is_complete);

        SP1GlobalContext::commit_recursion_public_values(builder, *compress_public_values);
    }
}
