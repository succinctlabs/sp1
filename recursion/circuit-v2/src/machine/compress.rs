use std::{
    array,
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
};

use itertools::{izip, Itertools};
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;

use p3_commit::Mmcs;
use p3_matrix::dense::RowMajorMatrix;
use sp1_core::{
    air::{MachineAir, Word, POSEIDON_NUM_WORDS, PV_DIGEST_NUM_WORDS},
    stark::{ShardProof, StarkGenericConfig, StarkMachine, StarkVerifyingKey},
    utils::DIGEST_SIZE,
};
use sp1_recursion_compiler::ir::{Builder, Felt};
use sp1_recursion_core_v2::{
    air::{ChallengerPublicValues, RecursionPublicValues, RECURSIVE_PROOF_NUM_PV_ELTS},
    D,
};
// TODO: Migrate this type to here.
use sp1_recursion_program::machine::ReduceProgramType;

use crate::{
    challenger::CanObserveVariable,
    stark::StarkVerifier,
    utils::{assign_challenger_pv, commit_recursion_public_values, uninit_challenger_pv},
};
use crate::{
    constraints::RecursiveVerifierConstraintFolder, stark::ShardProofVariable,
    BabyBearFriConfigVariable, CircuitConfig, VerifyingKeyVariable,
};

/// A program to verify a batch of recursive proofs and aggregate their public values.
#[derive(Debug, Clone, Copy)]
pub struct SP1CompressVerifier<C, SC, A> {
    _phantom: PhantomData<(C, SC, A)>,
}

/// Witness layout for the compress stage verifier.
pub struct SP1CompressWitnessVariable<
    C: CircuitConfig<F = BabyBear>,
    SC: BabyBearFriConfigVariable<C>,
> {
    /// The shard proofs to verify.
    pub vks_and_proofs: Vec<(VerifyingKeyVariable<C, SC>, ShardProofVariable<C, SC>)>,
    pub is_complete: Felt<C::F>,
    pub kinds: Vec<ReduceProgramType>,
}

/// An input layout for the reduce verifier.
pub struct SP1CompressWitnessValues<SC: StarkGenericConfig> {
    pub vks_and_proofs: Vec<(StarkVerifyingKey<SC>, ShardProof<SC>)>,
    pub is_complete: bool,
    pub kinds: Vec<ReduceProgramType>,
}

impl<C, SC, A> SP1CompressVerifier<C, SC, A>
where
    SC: BabyBearFriConfigVariable<C>,
    C: CircuitConfig<F = SC::Val, EF = SC::Challenge, Bit = Felt<BabyBear>>,
    <SC::ValMmcs as Mmcs<BabyBear>>::ProverData<RowMajorMatrix<BabyBear>>: Clone,
    A: MachineAir<SC::Val> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
{
    /// Verify a batch of recursive proofs and aggregate their public values.
    ///
    /// The compression verifier can aggregate proofs of different kinds:
    /// - Core proofs: proofs which are recursive proof of a batch of SP1 shard proofs. The
    ///   implementation in this function assumes a fixed recursive verifier speicified by
    ///   `recursive_vk`.
    /// - Deferred proofs: proofs which are recursive proof of a batch of deferred proofs. The
    ///   implementation in this function assumes a fixed deferred verification program specified
    ///   by `deferred_vk`.
    /// - Compress proofs: these are proofs which refer to a prove of this program. The key for
    ///   it is part of public values will be propagated accross all levels of recursion and will
    ///   be checked against itself as in [sp1_prover::Prover] or as in [super::SP1RootVerifier].
    pub fn verify(
        builder: &mut Builder<C>,
        machine: &StarkMachine<SC, A>,
        input: SP1CompressWitnessVariable<C, SC>,
        // TODO: add vk correctness check.
        // vk_root: SC::Digest,
        // Inclusion proof for the compressed vk.
        // vk_inclusion_proof: proof,
    ) {
        // Read input.
        let SP1CompressWitnessVariable {
            vks_and_proofs,
            is_complete,
            kinds: _,
        } = input;

        // Initialize the values for the aggregated public output.

        let mut reduce_public_values_stream: Vec<Felt<_>> = (0..RECURSIVE_PROOF_NUM_PV_ELTS)
            .map(|_| builder.uninit())
            .collect();
        let compress_public_values: &mut RecursionPublicValues<_> =
            reduce_public_values_stream.as_mut_slice().borrow_mut();

        // TODO: add vk correctness check.

        // Make sure there is at least one proof.
        assert!(!vks_and_proofs.is_empty());

        // Initialize the consistency check variables.
        let sp1_vk_digest: [Felt<_>; DIGEST_SIZE] = array::from_fn(|_| builder.uninit());
        let pc: Felt<_> = builder.uninit();
        let shard: Felt<_> = builder.uninit();
        let execution_shard: Felt<_> = builder.uninit();
        let mut initial_reconstruct_challenger_values: ChallengerPublicValues<Felt<C::F>> =
            uninit_challenger_pv(builder);
        let mut reconstruct_challenger_values: ChallengerPublicValues<Felt<C::F>> =
            uninit_challenger_pv(builder);
        let mut leaf_challenger_values: ChallengerPublicValues<Felt<C::F>> =
            uninit_challenger_pv(builder);
        let committed_value_digest: [Word<Felt<_>>; PV_DIGEST_NUM_WORDS] =
            array::from_fn(|_| Word(array::from_fn(|_| builder.uninit())));
        let deferred_proofs_digest: [Felt<_>; POSEIDON_NUM_WORDS] =
            array::from_fn(|_| builder.uninit());
        let reconstruct_deferred_digest: [Felt<_>; POSEIDON_NUM_WORDS] =
            core::array::from_fn(|_| builder.uninit());
        let cumulative_sum: [Felt<_>; D] = core::array::from_fn(|_| builder.eval(C::F::zero()));
        let init_addr_bits: [Felt<_>; 32] = core::array::from_fn(|_| builder.uninit());
        let finalize_addr_bits: [Felt<_>; 32] = core::array::from_fn(|_| builder.uninit());

        // Verify proofs, check consistency, and aggregate public values.
        for (i, (vk, shard_proof)) in vks_and_proofs.into_iter().enumerate() {
            // Verify the shard proof.

            // Prepare a challenger.
            let mut challenger = machine.config().challenger_variable(builder);

            // Observe the vk and start pc.
            challenger.observe(builder, vk.commitment);
            challenger.observe(builder, vk.pc_start);

            // Observe the main commitment and public values.
            challenger.observe(builder, shard_proof.commitment.main_commit);
            challenger.observe_slice(
                builder,
                shard_proof.public_values[0..machine.num_pv_elts()]
                    .iter()
                    .copied(),
            );
            StarkVerifier::verify_shard(builder, &vk, machine, &mut challenger, &shard_proof);

            // Get the current public values.
            let current_public_values: &RecursionPublicValues<Felt<C::F>> =
                shard_proof.public_values.as_slice().borrow();

            if i == 0 {
                // Initialize global and accumulated values.

                // Initialize the start of deferred digests.
                for (digest, current_digest, global_digest) in izip!(
                    reconstruct_deferred_digest.iter(),
                    current_public_values
                        .start_reconstruct_deferred_digest
                        .iter(),
                    compress_public_values
                        .start_reconstruct_deferred_digest
                        .iter()
                ) {
                    builder.assign(*digest, *current_digest);
                    builder.assign(*global_digest, *current_digest);
                }

                // Initialize the sp1_vk digest
                for (digest, first_digest) in sp1_vk_digest
                    .iter()
                    .zip(current_public_values.sp1_vk_digest)
                {
                    builder.assign(*digest, first_digest);
                }

                // Initiallize start pc.
                builder.assign(
                    compress_public_values.start_pc,
                    current_public_values.start_pc,
                );
                builder.assign(pc, current_public_values.start_pc);

                // Initialize start shard.
                builder.assign(shard, current_public_values.start_shard);
                builder.assign(
                    compress_public_values.start_shard,
                    current_public_values.start_shard,
                );

                // Initialize start execution shard.
                builder.assign(execution_shard, current_public_values.start_execution_shard);
                builder.assign(
                    compress_public_values.start_execution_shard,
                    current_public_values.start_execution_shard,
                );

                // Initialize the MemoryInitialize address bits.
                for (bit, (first_bit, current_bit)) in init_addr_bits.iter().zip(
                    compress_public_values
                        .previous_init_addr_bits
                        .iter()
                        .zip(current_public_values.previous_init_addr_bits.iter()),
                ) {
                    builder.assign(*bit, *current_bit);
                    builder.assign(*first_bit, *current_bit);
                }

                // Initialize the MemoryFinalize address bits.
                for (bit, (first_bit, current_bit)) in finalize_addr_bits.iter().zip(
                    compress_public_values
                        .previous_finalize_addr_bits
                        .iter()
                        .zip(current_public_values.previous_finalize_addr_bits.iter()),
                ) {
                    builder.assign(*bit, *current_bit);
                    builder.assign(*first_bit, *current_bit);
                }

                // Initialize the leaf challenger public values.
                leaf_challenger_values = current_public_values.leaf_challenger;
                // Initialize the reconstruct challenger public values.
                reconstruct_challenger_values = current_public_values.start_reconstruct_challenger;
                // Initialize the initial reconstruct challenger public values.
                initial_reconstruct_challenger_values =
                    current_public_values.start_reconstruct_challenger;

                // Assign the commited values and deferred proof digests.
                for (word, current_word) in committed_value_digest
                    .iter()
                    .zip_eq(current_public_values.committed_value_digest.iter())
                {
                    for (byte, current_byte) in word.0.iter().zip_eq(current_word.0.iter()) {
                        builder.assign(*byte, *current_byte);
                    }
                }

                for (digest, current_digest) in deferred_proofs_digest
                    .iter()
                    .zip_eq(current_public_values.deferred_proofs_digest.iter())
                {
                    builder.assign(*digest, *current_digest);
                }
            }

            // Assert that the current values match the accumulated values.

            // // Assert that the start deferred digest is equal to the current deferred digest.
            // for (digest, current_digest) in reconstruct_deferred_digest.iter().zip_eq(
            //     current_public_values
            //         .start_reconstruct_deferred_digest
            //         .iter(),
            // ) {
            //     builder.assert_felt_eq(*digest, *current_digest);
            // }

            // // Consistency checks for all accumulated values.

            // // Assert that the sp1_vk digest is always the same.
            // for (digest, current) in sp1_vk_digest
            //     .iter()
            //     .zip(current_public_values.sp1_vk_digest)
            // {
            //     builder.assert_felt_eq(*digest, current);
            // }

            // // Assert that the start pc is equal to the current pc.
            // builder.assert_felt_eq(pc, current_public_values.start_pc);

            // // Verify that the shard is equal to the current shard.
            // builder.assert_felt_eq(shard, current_public_values.start_shard);

            // // Verfiy that the exeuction shard is equal to the current execution shard.
            // builder.assert_felt_eq(execution_shard, current_public_values.start_execution_shard);

            // // Assert that the leaf challenger is always the same.

            // // Assert that the MemoryInitialize address bits are the same.
            // for (bit, current_bit) in init_addr_bits
            //     .iter()
            //     .zip(current_public_values.previous_init_addr_bits.iter())
            // {
            //     builder.assert_felt_eq(*bit, *current_bit);
            // }

            // // Assert that the MemoryFinalize address bits are the same.
            // for (bit, current_bit) in finalize_addr_bits
            //     .iter()
            //     .zip(current_public_values.previous_finalize_addr_bits.iter())
            // {
            //     builder.assert_felt_eq(*bit, *current_bit);
            // }

            // Assert that the leaf challenger is always the same.

            // assert_challenger_eq_pv(
            //     builder,
            //     &leaf_challenger,
            //     current_public_values.leaf_challenger,
            // );
            // // Assert that the current challenger matches the start reconstruct challenger.
            // assert_challenger_eq_pv(
            //     builder,
            //     &reconstruct_challenger,
            //     current_public_values.start_reconstruct_challenger,
            // );

            // Digest constraints.
            {
                // // If `commited_value_digest` is not zero, then `public_values.commited_value_digest
                // // should be the current value.
                // let is_zero: Var<_> = builder.eval(C::N::one());
                // #[allow(clippy::needless_range_loop)]
                // for i in 0..committed_value_digest.len() {
                //     for j in 0..WORD_SIZE {
                //         let d = felt2var(builder, committed_value_digest[i][j]);
                //         builder.if_ne(d, C::N::zero()).then(|builder| {
                //             builder.assign(is_zero, C::N::zero());
                //         });
                //     }
                // }
                // builder.if_eq(is_zero, C::N::zero()).then(|builder| {
                //     #[allow(clippy::needless_range_loop)]
                //     for i in 0..committed_value_digest.len() {
                //         for j in 0..WORD_SIZE {
                //             builder.assert_felt_eq(
                //                 committed_value_digest[i][j],
                //                 current_public_values.committed_value_digest[i][j],
                //             );
                //         }
                //     }
                // });

                // Update the committed value digest.
                for (word, current_word) in committed_value_digest
                    .iter()
                    .zip_eq(current_public_values.committed_value_digest.iter())
                {
                    for (byte, current_byte) in word.0.iter().zip_eq(current_word.0.iter()) {
                        builder.assign(*byte, *current_byte);
                    }
                }
                // Less nice version of above but simialr to original code:
                // for i in 0..committed_value_digest.len() {
                //     for j in 0..WORD_SIZE {
                //         builder.assign(
                //             committed_value_digest[i][j],
                //             current_public_values.committed_value_digest[i][j],
                //         );
                //     }
                // }

                // // If `deferred_proofs_digest` is not zero, then `public_values.deferred_proofs_digest
                // // should be the current value.
                // let is_zero: Var<_> = builder.eval(C::N::one());
                // #[allow(clippy::needless_range_loop)]
                // for i in 0..deferred_proofs_digest.len() {
                //     let d = felt2var(builder, deferred_proofs_digest[i]);
                //     builder.if_ne(d, C::N::zero()).then(|builder| {
                //         builder.assign(is_zero, C::N::zero());
                //     });
                // }
                // builder.if_eq(is_zero, C::N::zero()).then(|builder| {
                //     #[allow(clippy::needless_range_loop)]
                //     for i in 0..deferred_proofs_digest.len() {
                //         builder.assert_felt_eq(
                //             deferred_proofs_digest[i],
                //             current_public_values.deferred_proofs_digest[i],
                //         );
                //     }
                // });

                // Update the deferred proofs digest.
                for (digest, current_digest) in deferred_proofs_digest
                    .iter()
                    .zip_eq(current_public_values.deferred_proofs_digest.iter())
                {
                    builder.assign(*digest, *current_digest);
                }

                // Less nice version of above but simialr to original code:
                // #[allow(clippy::needless_range_loop)]
                // for i in 0..deferred_proofs_digest.len() {
                //     builder.assign(
                //         deferred_proofs_digest[i],
                //         current_public_values.deferred_proofs_digest[i],
                //     );
                // }
            }

            // Update the deferred proof digest.
            for (digest, current_digest) in reconstruct_deferred_digest
                .iter()
                .zip_eq(current_public_values.end_reconstruct_deferred_digest.iter())
            {
                builder.assign(*digest, *current_digest);
            }

            // Update the accumulated values.
            // Update pc to be the next pc.
            builder.assign(pc, current_public_values.next_pc);

            // Update the shard to be the next shard.
            builder.assign(shard, current_public_values.next_shard);

            // Update the execution shard to be the next execution shard.
            builder.assign(execution_shard, current_public_values.next_execution_shard);

            // Update the MemoryInitialize address bits.
            for (bit, next_bit) in init_addr_bits
                .iter()
                .zip(current_public_values.last_init_addr_bits.iter())
            {
                builder.assign(*bit, *next_bit);
            }

            // Update the MemoryFinalize address bits.
            for (bit, next_bit) in finalize_addr_bits
                .iter()
                .zip(current_public_values.last_finalize_addr_bits.iter())
            {
                builder.assign(*bit, *next_bit);
            }

            // Update the reconstruct challenger.
            assign_challenger_pv(
                builder,
                &mut reconstruct_challenger_values,
                &current_public_values.end_reconstruct_challenger,
            );

            // Update the cumulative sum.
            for (sum_element, current_sum_element) in cumulative_sum
                .iter()
                .zip_eq(current_public_values.cumulative_sum.iter())
            {
                builder.assign(*sum_element, *sum_element + *current_sum_element);
            }
        }

        // Update the global values from the last accumulated values.
        // Set sp1_vk digest to the one from the proof values.
        compress_public_values.sp1_vk_digest = sp1_vk_digest;
        // Set next_pc to be the last pc (which is the same as accumulated pc)
        compress_public_values.next_pc = pc;
        // Set next shard to be the last shard
        compress_public_values.next_shard = shard;
        // Set next execution shard to be the last execution shard
        compress_public_values.next_execution_shard = execution_shard;
        // Set the MemoryInitialize address bits to be the last MemoryInitialize address bits.
        compress_public_values.last_init_addr_bits = init_addr_bits;
        // Set the MemoryFinalize address bits to be the last MemoryFinalize address bits.
        compress_public_values.last_finalize_addr_bits = finalize_addr_bits;
        // Set the leaf challenger to it's value.
        compress_public_values.leaf_challenger = leaf_challenger_values;
        // Set the start reconstruct challenger to be the initial reconstruct challenger.
        compress_public_values.start_reconstruct_challenger = initial_reconstruct_challenger_values;
        // Set the end reconstruct challenger to be the last reconstruct challenger.
        compress_public_values.end_reconstruct_challenger = reconstruct_challenger_values;
        // Set the start reconstruct deferred digest to be the last reconstruct deferred digest.
        compress_public_values.end_reconstruct_deferred_digest = reconstruct_deferred_digest;
        // Assign the deferred proof digests.
        compress_public_values.deferred_proofs_digest = deferred_proofs_digest;
        // Assign the committed value digests.
        compress_public_values.committed_value_digest = committed_value_digest;
        // Assign the cumulative sum.
        compress_public_values.cumulative_sum = cumulative_sum;
        // Assign the `is_complete` flag.
        compress_public_values.is_complete = is_complete;

        // // If the proof is complete, make completeness assertions and set the flag. Otherwise, check
        // // the flag is zero and set the public value to zero.
        // builder.if_eq(is_complete, C::N::one()).then_or_else(
        //     |builder| {
        //         builder.assign(compress_public_values.is_complete, C::F::one());
        //         assert_complete(builder, compress_public_values, &reconstruct_challenger)
        //     },
        //     |builder| {
        //         builder.assert_var_eq(is_complete, C::N::zero());
        //         builder.assign(compress_public_values.is_complete, C::F::zero());
        //     },
        // );

        commit_recursion_public_values(builder, compress_public_values);
    }
}
