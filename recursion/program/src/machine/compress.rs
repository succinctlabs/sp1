use std::array;
use std::borrow::{Borrow, BorrowMut};
use std::marker::PhantomData;

use crate::machine::utils::assert_complete;
use itertools::{izip, Itertools};
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{AbstractField, PrimeField32, TwoAdicField};
use serde::{Deserialize, Serialize};
use sp1_core::air::{MachineAir, WORD_SIZE};
use sp1_core::air::{Word, POSEIDON_NUM_WORDS, PV_DIGEST_NUM_WORDS};
use sp1_core::stark::StarkMachine;
use sp1_core::stark::{Com, ShardProof, StarkGenericConfig, StarkVerifyingKey};
use sp1_core::utils::BabyBearPoseidon2;
use sp1_primitives::types::RecursionProgramType;
use sp1_recursion_compiler::config::InnerConfig;
use sp1_recursion_compiler::ir::{Array, Builder, Config, Felt, Var};
use sp1_recursion_compiler::prelude::DslVariable;
use sp1_recursion_core::air::{RecursionPublicValues, RECURSIVE_PROOF_NUM_PV_ELTS};
use sp1_recursion_core::runtime::{RecursionProgram, D, DIGEST_SIZE};

use sp1_recursion_compiler::prelude::*;

use crate::challenger::{CanObserveVariable, DuplexChallengerVariable};
use crate::fri::TwoAdicFriPcsVariable;
use crate::hints::Hintable;
use crate::stark::{RecursiveVerifierConstraintFolder, StarkVerifier};
use crate::types::ShardProofVariable;
use crate::types::VerifyingKeyVariable;
use crate::utils::{
    assert_challenger_eq_pv, assign_challenger_from_pv, const_fri_config, felt2var,
    get_challenger_public_values, hash_vkey,
};

use super::utils::{commit_public_values, proof_data_from_vk, verify_public_values_hash};

/// A program to verify a batch of recursive proofs and aggregate their public values.
#[derive(Debug, Clone, Copy)]
pub struct SP1CompressVerifier<C: Config, SC: StarkGenericConfig, A> {
    _phantom: PhantomData<(C, SC, A)>,
}

/// The different types of programs that can be verified by the `SP1ReduceVerifier`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ReduceProgramType {
    /// A batch of proofs that are all SP1 Core proofs.
    Core = 0,
    /// A batch of proofs that are all deferred proofs.
    Deferred = 1,
    /// A batch of proofs that are reduce proofs of a higher level in the recursion tree.
    Reduce = 2,
}

/// An input layout for the reduce verifier.
pub struct SP1ReduceMemoryLayout<'a, SC: StarkGenericConfig, A: MachineAir<SC::Val>> {
    pub compress_vk: &'a StarkVerifyingKey<SC>,
    pub recursive_machine: &'a StarkMachine<SC, A>,
    pub shard_proofs: Vec<ShardProof<SC>>,
    pub is_complete: bool,
    pub kinds: Vec<ReduceProgramType>,
}

#[derive(DslVariable, Clone)]
pub struct SP1ReduceMemoryLayoutVariable<C: Config> {
    pub compress_vk: VerifyingKeyVariable<C>,
    pub shard_proofs: Array<C, ShardProofVariable<C>>,
    pub kinds: Array<C, Var<C::N>>,
    pub is_complete: Var<C::N>,
}

impl<A> SP1CompressVerifier<InnerConfig, BabyBearPoseidon2, A>
where
    A: MachineAir<BabyBear> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, InnerConfig>>,
{
    /// Create a new instance of the program for the [BabyBearPoseidon2] config.
    pub fn build(
        machine: &StarkMachine<BabyBearPoseidon2, A>,
        recursive_vk: &StarkVerifyingKey<BabyBearPoseidon2>,
        deferred_vk: &StarkVerifyingKey<BabyBearPoseidon2>,
    ) -> RecursionProgram<BabyBear> {
        let mut builder = Builder::<InnerConfig>::new(RecursionProgramType::Compress);

        let input: SP1ReduceMemoryLayoutVariable<_> = builder.uninit();
        SP1ReduceMemoryLayout::<BabyBearPoseidon2, A>::witness(&input, &mut builder);

        let pcs = TwoAdicFriPcsVariable {
            config: const_fri_config(&mut builder, machine.config().pcs().fri_config()),
        };
        SP1CompressVerifier::verify(
            &mut builder,
            &pcs,
            machine,
            input,
            recursive_vk,
            deferred_vk,
        );

        builder.halt();

        builder.compile_program()
    }
}

impl<C: Config, SC, A> SP1CompressVerifier<C, SC, A>
where
    C::F: PrimeField32 + TwoAdicField,
    SC: StarkGenericConfig<
        Val = C::F,
        Challenge = C::EF,
        Domain = TwoAdicMultiplicativeCoset<C::F>,
    >,
    A: MachineAir<C::F> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
    Com<SC>: Into<[SC::Val; DIGEST_SIZE]>,
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
        pcs: &TwoAdicFriPcsVariable<C>,
        machine: &StarkMachine<SC, A>,
        input: SP1ReduceMemoryLayoutVariable<C>,
        recursive_vk: &StarkVerifyingKey<SC>,
        deferred_vk: &StarkVerifyingKey<SC>,
    ) {
        let SP1ReduceMemoryLayoutVariable {
            compress_vk,
            shard_proofs,
            kinds,
            is_complete,
        } = input;

        // Initialize the values for the aggregated public output.

        let mut reduce_public_values_stream: Vec<Felt<_>> = (0..RECURSIVE_PROOF_NUM_PV_ELTS)
            .map(|_| builder.uninit())
            .collect();
        let reduce_public_values: &mut RecursionPublicValues<_> =
            reduce_public_values_stream.as_mut_slice().borrow_mut();

        // Compute the digest of compress_vk and input the value to the public values.
        let compress_vk_digest = hash_vkey(builder, &compress_vk);

        reduce_public_values.compress_vk_digest =
            array::from_fn(|i| builder.get(&compress_vk_digest, i));

        // Assert that there is at least one proof.
        builder.assert_usize_ne(shard_proofs.len(), 0);

        // Assert that the number of proofs is equal to the number of kinds.
        builder.assert_usize_eq(shard_proofs.len(), kinds.len());

        // Initialize the consistency check variables.
        let sp1_vk_digest: [Felt<_>; DIGEST_SIZE] = array::from_fn(|_| builder.uninit());
        let pc: Felt<_> = builder.uninit();
        let shard: Felt<_> = builder.uninit();
        let execution_shard: Felt<_> = builder.uninit();
        let mut initial_reconstruct_challenger = DuplexChallengerVariable::new(builder);
        let mut reconstruct_challenger = DuplexChallengerVariable::new(builder);
        let mut leaf_challenger = DuplexChallengerVariable::new(builder);
        let committed_value_digest: [Word<Felt<_>>; PV_DIGEST_NUM_WORDS] =
            array::from_fn(|_| Word(array::from_fn(|_| builder.uninit())));
        let deferred_proofs_digest: [Felt<_>; POSEIDON_NUM_WORDS] =
            array::from_fn(|_| builder.uninit());
        let reconstruct_deferred_digest: [Felt<_>; POSEIDON_NUM_WORDS] =
            core::array::from_fn(|_| builder.uninit());
        let cumulative_sum: [Felt<_>; D] = core::array::from_fn(|_| builder.eval(C::F::zero()));
        let init_addr_bits: [Felt<_>; 32] = core::array::from_fn(|_| builder.uninit());
        let finalize_addr_bits: [Felt<_>; 32] = core::array::from_fn(|_| builder.uninit());

        // Collect verifying keys for each kind of program.
        let recursive_vk_variable = proof_data_from_vk(builder, recursive_vk, machine);
        let deferred_vk_variable = proof_data_from_vk(builder, deferred_vk, machine);

        // Get field values for the proof kind.
        let core_kind = C::N::from_canonical_u32(ReduceProgramType::Core as u32);
        let deferred_kind = C::N::from_canonical_u32(ReduceProgramType::Deferred as u32);
        let reduce_kind = C::N::from_canonical_u32(ReduceProgramType::Reduce as u32);

        // Verify the shard proofs and connect the values.
        builder.range(0, shard_proofs.len()).for_each(|i, builder| {
            // Load the proof.
            let proof = builder.get(&shard_proofs, i);

            // Get the kind of proof we are verifying.
            let kind = builder.get(&kinds, i);

            // Verify the shard proof.

            // Initialize values for verifying key and proof data.
            let vk: VerifyingKeyVariable<_> = builder.uninit();

            // Set the correct value given the value of kind, and assert it must be one of the
            // valid values. We can do that by nested `if-else` statements.
            builder.if_eq(kind, core_kind).then_or_else(
                |builder| {
                    builder.assign(vk.clone(), recursive_vk_variable.clone());
                },
                |builder| {
                    builder.if_eq(kind, deferred_kind).then_or_else(
                        |builder| {
                            builder.assign(vk.clone(), deferred_vk_variable.clone());
                        },
                        |builder| {
                            builder.if_eq(kind, reduce_kind).then_or_else(
                                |builder| {
                                    builder.assign(vk.clone(), compress_vk.clone());
                                },
                                |builder| {
                                    // If the kind is not one of the valid values, raise an error.
                                    builder.error();
                                },
                            );
                        },
                    );
                },
            );

            // Verify the shard proof given the correct data.

            // Prepare a challenger.
            let mut challenger = DuplexChallengerVariable::new(builder);

            // Observe the vk and start pc.
            challenger.observe(builder, vk.commitment.clone());
            challenger.observe(builder, vk.pc_start);

            // Observe the main commitment and public values.
            challenger.observe(builder, proof.commitment.main_commit.clone());
            for j in 0..machine.num_pv_elts() {
                let element = builder.get(&proof.public_values, j);
                challenger.observe(builder, element);
            }

            // Verify proof.
            StarkVerifier::<C, SC>::verify_shard(
                builder,
                &vk,
                pcs,
                machine,
                &mut challenger,
                &proof,
                true,
            );

            // Load the public values from the proof.
            let current_public_values_elements = (0..RECURSIVE_PROOF_NUM_PV_ELTS)
                .map(|i| builder.get(&proof.public_values, i))
                .collect::<Vec<Felt<_>>>();

            let current_public_values: &RecursionPublicValues<Felt<C::F>> =
                current_public_values_elements.as_slice().borrow();

            // Check that the public values digest is correct.
            verify_public_values_hash(builder, current_public_values);

            // If the proof is the first proof, initialize the values.
            builder.if_eq(i, C::N::zero()).then(|builder| {
                // Initialize global and accumulated values.

                // Initialize the start of deferred digests.
                for (digest, current_digest, global_digest) in izip!(
                    reconstruct_deferred_digest.iter(),
                    current_public_values
                        .start_reconstruct_deferred_digest
                        .iter(),
                    reduce_public_values
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
                    reduce_public_values.start_pc,
                    current_public_values.start_pc,
                );
                builder.assign(pc, current_public_values.start_pc);

                // Initialize start shard.
                builder.assign(shard, current_public_values.start_shard);
                builder.assign(
                    reduce_public_values.start_shard,
                    current_public_values.start_shard,
                );

                // Initialize start execution shard.
                builder.assign(execution_shard, current_public_values.start_execution_shard);
                builder.assign(
                    reduce_public_values.start_execution_shard,
                    current_public_values.start_execution_shard,
                );

                // Initialize the MemoryInitialize address bits.
                for (bit, (first_bit, current_bit)) in init_addr_bits.iter().zip(
                    reduce_public_values
                        .previous_init_addr_bits
                        .iter()
                        .zip(current_public_values.previous_init_addr_bits.iter()),
                ) {
                    builder.assign(*bit, *current_bit);
                    builder.assign(*first_bit, *current_bit);
                }

                // Initialize the MemoryFinalize address bits.
                for (bit, (first_bit, current_bit)) in finalize_addr_bits.iter().zip(
                    reduce_public_values
                        .previous_finalize_addr_bits
                        .iter()
                        .zip(current_public_values.previous_finalize_addr_bits.iter()),
                ) {
                    builder.assign(*bit, *current_bit);
                    builder.assign(*first_bit, *current_bit);
                }

                // Initialize the leaf challenger.
                assign_challenger_from_pv(
                    builder,
                    &mut leaf_challenger,
                    current_public_values.leaf_challenger,
                );

                // Initialize the reconstruct challenger.
                assign_challenger_from_pv(
                    builder,
                    &mut initial_reconstruct_challenger,
                    current_public_values.start_reconstruct_challenger,
                );
                assign_challenger_from_pv(
                    builder,
                    &mut reconstruct_challenger,
                    current_public_values.start_reconstruct_challenger,
                );

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
            });

            // Assert that the current values match the accumulated values.

            // Assert that the start deferred digest is equal to the current deferred digest.
            for (digest, current_digest) in reconstruct_deferred_digest.iter().zip_eq(
                current_public_values
                    .start_reconstruct_deferred_digest
                    .iter(),
            ) {
                builder.assert_felt_eq(*digest, *current_digest);
            }

            // Consistency checks for all accumulated values.

            // Assert that the sp1_vk digest is always the same.
            for (digest, current) in sp1_vk_digest
                .iter()
                .zip(current_public_values.sp1_vk_digest)
            {
                builder.assert_felt_eq(*digest, current);
            }

            // Assert that the start pc is equal to the current pc.
            builder.assert_felt_eq(pc, current_public_values.start_pc);

            // Verify that the shard is equal to the current shard.
            builder.assert_felt_eq(shard, current_public_values.start_shard);

            // Verfiy that the exeuction shard is equal to the current execution shard.
            builder.assert_felt_eq(execution_shard, current_public_values.start_execution_shard);

            // Assert that the leaf challenger is always the same.

            // Assert that the MemoryInitialize address bits are the same.
            for (bit, current_bit) in init_addr_bits
                .iter()
                .zip(current_public_values.previous_init_addr_bits.iter())
            {
                builder.assert_felt_eq(*bit, *current_bit);
            }

            // Assert that the MemoryFinalize address bits are the same.
            for (bit, current_bit) in finalize_addr_bits
                .iter()
                .zip(current_public_values.previous_finalize_addr_bits.iter())
            {
                builder.assert_felt_eq(*bit, *current_bit);
            }

            assert_challenger_eq_pv(
                builder,
                &leaf_challenger,
                current_public_values.leaf_challenger,
            );
            // Assert that the current challenger matches the start reconstruct challenger.
            assert_challenger_eq_pv(
                builder,
                &reconstruct_challenger,
                current_public_values.start_reconstruct_challenger,
            );

            // Digest constraints.
            {
                // If `commited_value_digest` is not zero, then `public_values.commited_value_digest
                // should be the current value.
                let is_zero: Var<_> = builder.eval(C::N::one());
                #[allow(clippy::needless_range_loop)]
                for i in 0..committed_value_digest.len() {
                    for j in 0..WORD_SIZE {
                        let d = felt2var(builder, committed_value_digest[i][j]);
                        builder.if_ne(d, C::N::zero()).then(|builder| {
                            builder.assign(is_zero, C::N::zero());
                        });
                    }
                }
                builder.if_eq(is_zero, C::N::zero()).then(|builder| {
                    #[allow(clippy::needless_range_loop)]
                    for i in 0..committed_value_digest.len() {
                        for j in 0..WORD_SIZE {
                            builder.assert_felt_eq(
                                committed_value_digest[i][j],
                                current_public_values.committed_value_digest[i][j],
                            );
                        }
                    }
                });

                // Update the committed value digest.
                #[allow(clippy::needless_range_loop)]
                for i in 0..committed_value_digest.len() {
                    for j in 0..WORD_SIZE {
                        builder.assign(
                            committed_value_digest[i][j],
                            current_public_values.committed_value_digest[i][j],
                        );
                    }
                }

                // If `deferred_proofs_digest` is not zero, then `public_values.deferred_proofs_digest
                // should be the current value.
                let is_zero: Var<_> = builder.eval(C::N::zero());
                #[allow(clippy::needless_range_loop)]
                for i in 0..deferred_proofs_digest.len() {
                    let d = felt2var(builder, deferred_proofs_digest[i]);
                    builder.if_ne(d, C::N::zero()).then(|builder| {
                        builder.assign(is_zero, C::N::zero());
                    });
                }
                builder.if_eq(is_zero, C::N::zero()).then(|builder| {
                    builder.assert_felt_eq(
                        deferred_proofs_digest[0],
                        current_public_values.deferred_proofs_digest[0],
                    );
                });

                // Update the deferred proofs digest.
                #[allow(clippy::needless_range_loop)]
                for i in 0..deferred_proofs_digest.len() {
                    builder.assign(
                        deferred_proofs_digest[i],
                        current_public_values.deferred_proofs_digest[i],
                    );
                }
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
            assign_challenger_from_pv(
                builder,
                &mut reconstruct_challenger,
                current_public_values.end_reconstruct_challenger,
            );

            // Update the cumulative sum.
            for (sum_element, current_sum_element) in cumulative_sum
                .iter()
                .zip_eq(current_public_values.cumulative_sum.iter())
            {
                builder.assign(*sum_element, *sum_element + *current_sum_element);
            }
        });

        // Update the global values from the last accumulated values.
        // Set sp1_vk digest to the one from the proof values.
        reduce_public_values.sp1_vk_digest = sp1_vk_digest;
        // Set next_pc to be the last pc (which is the same as accumulated pc)
        reduce_public_values.next_pc = pc;
        // Set next shard to be the last shard
        reduce_public_values.next_shard = shard;
        // Set next execution shard to be the last execution shard
        reduce_public_values.next_execution_shard = execution_shard;
        // Set the MemoryInitialize address bits to be the last MemoryInitialize address bits.
        reduce_public_values.last_init_addr_bits = init_addr_bits;
        // Set the MemoryFinalize address bits to be the last MemoryFinalize address bits.
        reduce_public_values.last_finalize_addr_bits = finalize_addr_bits;
        // Set the leaf challenger to it's value.
        let values = get_challenger_public_values(builder, &leaf_challenger);
        reduce_public_values.leaf_challenger = values;
        // Set the start reconstruct challenger to be the initial reconstruct challenger.
        let values = get_challenger_public_values(builder, &initial_reconstruct_challenger);
        reduce_public_values.start_reconstruct_challenger = values;
        // Set the end reconstruct challenger to be the last reconstruct challenger.
        let values = get_challenger_public_values(builder, &reconstruct_challenger);
        reduce_public_values.end_reconstruct_challenger = values;
        // Set the start reconstruct deferred digest to be the last reconstruct deferred digest.
        reduce_public_values.end_reconstruct_deferred_digest = reconstruct_deferred_digest;
        // Assign the deferred proof digests.
        reduce_public_values.deferred_proofs_digest = deferred_proofs_digest;
        // Assign the committed value digests.
        reduce_public_values.committed_value_digest = committed_value_digest;
        // Assign the cumulative sum.
        reduce_public_values.cumulative_sum = cumulative_sum;

        // If the proof is complete, make completeness assertions and set the flag. Otherwise, check
        // the flag is zero and set the public value to zero.
        builder.if_eq(is_complete, C::N::one()).then_or_else(
            |builder| {
                builder.assign(reduce_public_values.is_complete, C::F::one());
                assert_complete(builder, reduce_public_values, &reconstruct_challenger)
            },
            |builder| {
                builder.assert_var_eq(is_complete, C::N::zero());
                builder.assign(reduce_public_values.is_complete, C::F::zero());
            },
        );

        commit_public_values(builder, reduce_public_values);
    }
}
