use std::{
    array,
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
};

use itertools::Itertools;
use p3_baby_bear::BabyBear;
use p3_commit::Mmcs;
use p3_field::AbstractField;
use p3_matrix::dense::RowMajorMatrix;
use sp1_core_machine::riscv::RiscvAir;
use sp1_primitives::consts::WORD_SIZE;
use sp1_recursion_core_v2::air::PV_DIGEST_NUM_WORDS;
use sp1_stark::{
    air::{PublicValues, POSEIDON_NUM_WORDS},
    StarkMachine, Word,
};

use crate::{
    utils::commit_recursion_public_values, BabyBearFriConfig, BabyBearFriConfigVariable,
    CircuitConfig,
};

use sp1_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Config, Ext, ExtConst, Felt},
};

use sp1_recursion_core_v2::{
    air::{RecursionPublicValues, RECURSIVE_PROOF_NUM_PV_ELTS},
    DIGEST_SIZE,
};

use crate::{
    challenger::{CanObserveVariable, DuplexChallengerVariable},
    stark::{ShardProofVariable, StarkVerifier},
    VerifyingKeyVariable,
};

pub struct SP1RecursionWitnessVariable<
    C: CircuitConfig<F = BabyBear>,
    SC: BabyBearFriConfigVariable<C>,
> {
    pub vk: VerifyingKeyVariable<C, SC>,
    pub shard_proofs: Vec<ShardProofVariable<C, SC>>,
    pub leaf_challenger: SC::FriChallengerVariable,
    pub initial_reconstruct_challenger: DuplexChallengerVariable<C>,
    pub is_complete: Felt<C::F>,
}

/// A program for recursively verifying a batch of SP1 proofs.
#[derive(Debug, Clone, Copy)]
pub struct SP1RecursiveVerifier<C: Config, SC: BabyBearFriConfig> {
    _phantom: PhantomData<(C, SC)>,
}

impl<C, SC> SP1RecursiveVerifier<C, SC>
where
    SC: BabyBearFriConfigVariable<
        C,
        FriChallengerVariable = DuplexChallengerVariable<C>,
        Digest = [Felt<BabyBear>; DIGEST_SIZE],
    >,
    C: CircuitConfig<F = SC::Val, EF = SC::Challenge, Bit = Felt<BabyBear>>,
    <SC::ValMmcs as Mmcs<BabyBear>>::ProverData<RowMajorMatrix<BabyBear>>: Clone,
{
    /// Verify a batch of SP1 shard proofs and aggregate their public values.
    ///
    /// This program represents a first recursive step in the verification of an SP1 proof
    /// consisting of one or more shards. Each shard proof is verified and its public values are
    /// aggregated into a single set representing the start and end state of the program execution
    /// across all shards.
    ///
    /// # Constraints
    ///
    /// ## Verifying the STARK proofs.
    /// For each shard, the verifier asserts the correctness of the STARK proof which is composed
    /// of verifying the FRI proof for openings and verifying the constraints.
    ///
    /// ## Aggregating the shard public values.
    /// See [SP1Prover::verify] for the verification algorithm of a complete SP1 proof. In this
    /// function, we are aggregating several shard proofs and attesting to an aggregated state which
    /// represents all the shards.
    ///
    /// ## The leaf challenger.
    /// A key difference between the recursive tree verification and the complete one in
    /// [SP1Prover::verify] is that the recursive verifier has no way of reconstructing the
    /// chanllenger only from a part of the shard proof. Therefore, the value of the leaf challenger
    /// is witnessed in the program and the verifier asserts correctness given this challenger.
    /// In the course of the recursive verification, the challenger is reconstructed by observing
    /// the commitments one by one, and in the final step, the challenger is asserted to be the same
    /// as the one witnessed here.
    pub fn verify(
        builder: &mut Builder<C>,
        machine: &StarkMachine<SC, RiscvAir<SC::Val>>,
        input: SP1RecursionWitnessVariable<C, SC>,
    ) {
        // Read input.
        let SP1RecursionWitnessVariable {
            vk,
            shard_proofs,
            leaf_challenger,
            initial_reconstruct_challenger,
            is_complete,
        } = input;

        // Initialize shard variables.
        let initial_shard: Felt<_> = builder.uninit();
        let current_shard: Felt<_> = builder.uninit();

        // Initialize execution shard variables.
        let initial_execution_shard: Felt<_> = builder.uninit();
        let current_execution_shard: Felt<_> = builder.uninit();

        // Initialize program counter variables.
        let start_pc: Felt<_> = builder.uninit();
        let current_pc: Felt<_> = builder.uninit();

        // Initialize memory initialization and finalization variables.
        let initial_previous_init_addr_bits: [Felt<_>; 32] = array::from_fn(|_| builder.uninit());
        let initial_previous_finalize_addr_bits: [Felt<_>; 32] =
            array::from_fn(|_| builder.uninit());
        let current_init_addr_bits: [Felt<_>; 32] = array::from_fn(|_| builder.uninit());
        let current_finalize_addr_bits: [Felt<_>; 32] = array::from_fn(|_| builder.uninit());

        // Initialize the exit code variable.
        let exit_code: Felt<_> = builder.uninit();

        // Initialize the public values digest.
        let committed_value_digest: [Word<Felt<_>>; PV_DIGEST_NUM_WORDS] =
            array::from_fn(|_| Word(array::from_fn(|_| builder.uninit())));

        // Initialize the deferred proofs digest.
        let deferred_proofs_digest: [Felt<_>; POSEIDON_NUM_WORDS] =
            array::from_fn(|_| builder.uninit());

        // Initialize the challenger variables.
        let leaf_challenger_public_values = leaf_challenger.public_values(builder);
        let mut reconstruct_challenger: DuplexChallengerVariable<_> =
            initial_reconstruct_challenger.copy(builder);

        // Initialize the cumulative sum.
        let cumulative_sum: Ext<_, _> = builder.eval(C::EF::zero().cons());

        // Assert that the number of proofs is not zero.
        assert!(!shard_proofs.is_empty());

        // Verify proofs.
        for (i, shard_proof) in shard_proofs.into_iter().enumerate() {
            let contains_cpu = shard_proof.contains_cpu();
            let _contains_memory_init = shard_proof.contains_memory_init();
            let _contains_memory_finalize = shard_proof.contains_memory_finalize();

            // Get the public values.
            let public_values: &PublicValues<Word<Felt<_>>, Felt<_>> =
                shard_proof.public_values.as_slice().borrow();

            let _shard = public_values.shard;

            // If this is the first proof in the batch, initialize the variables.
            if i == 0 {
                // Shard.
                builder.assign(initial_shard, public_values.shard);
                builder.assign(current_shard, public_values.shard);

                // Execution shard.
                builder.assign(initial_execution_shard, public_values.execution_shard);
                builder.assign(current_execution_shard, public_values.execution_shard);

                // Program counter.
                builder.assign(start_pc, public_values.start_pc);
                builder.assign(current_pc, public_values.start_pc);

                // Memory initialization & finalization.
                for ((bit, pub_bit), first_bit) in current_init_addr_bits
                    .iter()
                    .zip(public_values.previous_init_addr_bits.iter())
                    .zip(initial_previous_init_addr_bits.iter())
                {
                    builder.assign(*bit, *pub_bit);
                    builder.assign(*first_bit, *pub_bit);
                }
                for ((bit, pub_bit), first_bit) in current_finalize_addr_bits
                    .iter()
                    .zip(public_values.previous_finalize_addr_bits.iter())
                    .zip(initial_previous_finalize_addr_bits.iter())
                {
                    builder.assign(*bit, *pub_bit);
                    builder.assign(*first_bit, *pub_bit);
                }

                // Exit code.
                builder.assign(exit_code, public_values.exit_code);

                // Commited public values digests.
                for (word, first_word) in committed_value_digest
                    .iter()
                    .zip_eq(public_values.committed_value_digest.iter())
                {
                    for (byte, first_byte) in word.0.iter().zip_eq(first_word.0.iter()) {
                        builder.assign(*byte, *first_byte);
                    }
                }

                // Deferred proofs digests.
                for (digest, first_digest) in deferred_proofs_digest
                    .iter()
                    .zip_eq(public_values.deferred_proofs_digest.iter())
                {
                    builder.assign(*digest, *first_digest);
                }
            }

            // // If the shard is the first shard, assert that the initial challenger is equal to a
            // // fresh challenger observing the verifier key and the initial pc.
            // let shard = felt2var(builder, public_values.shard);
            // builder.if_eq(shard, C::N::one()).then(|builder| {
            //     let mut first_initial_challenger = DuplexChallengerVariable::new(builder);
            //     first_initial_challenger.observe(builder, vk.commitment.clone());
            //     first_initial_challenger.observe(builder, vk.pc_start);
            //     initial_reconstruct_challenger.assert_eq(builder, &first_initial_challenger);
            // });

            // Verify the shard.
            //
            // Do not verify the cumulative sum here, since the permutation challenge is shared
            // between all shards.
            let mut challenger = leaf_challenger.copy(builder);
            StarkVerifier::<C, SC, _>::verify_shard(
                builder,
                &vk,
                machine,
                &mut challenger,
                &shard_proof,
            );

            // // First shard has a "CPU" constraint.
            // {
            //     builder.if_eq(shard, C::N::one()).then(|builder| {
            //         builder.assert_var_eq(contains_cpu, C::N::one());
            //     });
            // }

            // // CPU log degree bound check constraints.
            // {
            //     for (i, chip) in machine.chips().iter().enumerate() {
            //         if chip.name() == "CPU" {
            //             builder.if_eq(contains_cpu, C::N::one()).then(|builder| {
            //                 let index = builder.get(&proof.sorted_idxs, i);
            //                 let cpu_log_degree =
            //                     builder.get(&proof.opened_values.chips, index).log_degree;
            //                 let cpu_log_degree_lt_max: Var<_> = builder.eval(C::N::zero());
            //                 builder
            //                     .range(0, MAX_CPU_LOG_DEGREE + 1)
            //                     .for_each(|j, builder| {
            //                         builder.if_eq(j, cpu_log_degree).then(|builder| {
            //                             builder.assign(cpu_log_degree_lt_max, C::N::one());
            //                         });
            //                     });
            //                 builder.assert_var_eq(cpu_log_degree_lt_max, C::N::one());
            //             });
            //         }
            //     }
            // }

            // Shard constraints.
            {
                // Assert that the shard of the proof is equal to the current shard.
                builder.assert_felt_eq(current_shard, public_values.shard);

                // Increment the current shard by one.
                builder.assign(current_shard, current_shard + C::F::one());
            }

            // Execution shard constraints.
            // let execution_shard = felt2var(builder, public_values.execution_shard);
            {
                // If the shard has a "CPU" chip, then the execution shard should be incremented by
                // 1.
                if contains_cpu {
                    // Assert that the shard of the proof is equal to the current shard.
                    // builder.assert_felt_eq(current_execution_shard,
                    // public_values.execution_shard);

                    builder.assign(current_execution_shard, current_execution_shard + C::F::one());
                }
            }

            // Program counter constraints.
            {
                // // If it's the first shard (which is the first execution shard), then the
                // start_pc // should be vk.pc_start.
                // builder.if_eq(shard, C::N::one()).then(|builder| {
                //     builder.assert_felt_eq(public_values.start_pc, vk.pc_start);
                // });

                // // Assert that the start_pc of the proof is equal to the current pc.
                // builder.assert_felt_eq(current_pc, public_values.start_pc);

                // // If it's not a shard with "CPU", then assert that the start_pc equals the
                // next_pc. builder.if_ne(contains_cpu, C::N::one()).then(|builder|
                // {     builder.assert_felt_eq(public_values.start_pc,
                // public_values.next_pc); });

                // // If it's a shard with "CPU", then assert that the start_pc is not zero.
                // builder.if_eq(contains_cpu, C::N::one()).then(|builder| {
                //     builder.assert_felt_ne(public_values.start_pc, C::F::zero());
                // });

                // Update current_pc to be the end_pc of the current proof.
                builder.assign(current_pc, public_values.next_pc);
            }

            // Exit code constraints.
            {
                // Assert that the exit code is zero (success) for all proofs.
                builder.assert_felt_eq(exit_code, C::F::zero());
            }

            // Memory initialization & finalization constraints.
            {
                // // Assert that `init_addr_bits` and `finalize_addr_bits` are zero for the first
                // execution shard. builder.if_eq(execution_shard,
                // C::N::one()).then(|builder| {     // Assert that the
                // MemoryInitialize address bits are zero.     for bit in
                // current_init_addr_bits.iter() {         builder.assert_felt_eq(*
                // bit, C::F::zero());     }

                //     // Assert that the MemoryFinalize address bits are zero.
                //     for bit in current_finalize_addr_bits.iter() {
                //         builder.assert_felt_eq(*bit, C::F::zero());
                //     }
                // });

                // // Assert that the MemoryInitialize address bits match the current loop variable.
                // for (bit, current_bit) in current_init_addr_bits
                //     .iter()
                //     .zip_eq(public_values.previous_init_addr_bits.iter())
                // {
                //     builder.assert_felt_eq(*bit, *current_bit);
                // }

                // // Assert that the MemoryFinalize address bits match the current loop variable.
                // for (bit, current_bit) in current_finalize_addr_bits
                //     .iter()
                //     .zip_eq(public_values.previous_finalize_addr_bits.iter())
                // {
                //     builder.assert_felt_eq(*bit, *current_bit);
                // }

                // // Assert that if MemoryInit is not present, then the address bits are the same.
                // builder
                //     .if_ne(contains_memory_init, C::N::one())
                //     .then(|builder| {
                //         for (prev_bit, last_bit) in public_values
                //             .previous_init_addr_bits
                //             .iter()
                //             .zip_eq(public_values.last_init_addr_bits.iter())
                //         {
                //             builder.assert_felt_eq(*prev_bit, *last_bit);
                //         }
                //     });

                // // Assert that if MemoryFinalize is not present, then the address bits are the
                // same. builder
                //     .if_ne(contains_memory_finalize, C::N::one())
                //     .then(|builder| {
                //         for (prev_bit, last_bit) in public_values
                //             .previous_finalize_addr_bits
                //             .iter()
                //             .zip_eq(public_values.last_finalize_addr_bits.iter())
                //         {
                //             builder.assert_felt_eq(*prev_bit, *last_bit);
                //         }
                //     });

                // Update the MemoryInitialize address bits.
                for (bit, pub_bit) in
                    current_init_addr_bits.iter().zip(public_values.last_init_addr_bits.iter())
                {
                    builder.assign(*bit, *pub_bit);
                }

                // Update the MemoryFinalize address bits.
                for (bit, pub_bit) in current_finalize_addr_bits
                    .iter()
                    .zip(public_values.last_finalize_addr_bits.iter())
                {
                    builder.assign(*bit, *pub_bit);
                }
            }

            // Digest constraints.
            {
                // // If `commited_value_digest` is not zero, then
                // `public_values.commited_value_digest // should be the current
                // value. let is_zero: Var<_> = builder.eval(C::N::one());
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
                //                 public_values.committed_value_digest[i][j],
                //             );
                //         }
                //     }
                // });

                // // If it's not a shard with "CPU", then the committed value digest should not
                // change. builder.if_ne(contains_cpu, C::N::one()).then(|builder| {
                //     #[allow(clippy::needless_range_loop)]
                //     for i in 0..committed_value_digest.len() {
                //         for j in 0..WORD_SIZE {
                //             builder.assert_felt_eq(
                //                 committed_value_digest[i][j],
                //                 public_values.committed_value_digest[i][j],
                //             );
                //         }
                //     }
                // });

                // Update the committed value digest.
                #[allow(clippy::needless_range_loop)]
                for i in 0..committed_value_digest.len() {
                    for j in 0..WORD_SIZE {
                        builder.assign(
                            committed_value_digest[i][j],
                            public_values.committed_value_digest[i][j],
                        );
                    }
                }

                // // If `deferred_proofs_digest` is not zero, then
                // `public_values.deferred_proofs_digest // should be the current
                // value. let is_zero: Var<_> = builder.eval(C::N::one());
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
                //             public_values.deferred_proofs_digest[i],
                //         );
                //     }
                // });

                // // If it's not a shard with "CPU", then the deferred proofs digest should not
                // change. builder.if_ne(contains_cpu, C::N::one()).then(|builder| {
                //     #[allow(clippy::needless_range_loop)]
                //     for i in 0..deferred_proofs_digest.len() {
                //         builder.assert_felt_eq(
                //             deferred_proofs_digest[i],
                //             public_values.deferred_proofs_digest[i],
                //         );
                //     }
                // });

                // Update the deferred proofs digest.
                #[allow(clippy::needless_range_loop)]
                for i in 0..deferred_proofs_digest.len() {
                    builder
                        .assign(deferred_proofs_digest[i], public_values.deferred_proofs_digest[i]);
                }
            }

            // // Verify that the number of shards is not too large.
            // builder.range_check_f(public_values.shard, 16);

            // Update the reconstruct challenger.
            reconstruct_challenger.observe(builder, shard_proof.commitment.main_commit);
            for element in shard_proof.public_values.iter() {
                reconstruct_challenger.observe(builder, *element);
            }

            // Cumulative sum is updated by sums of all chips.
            for values in shard_proof.opened_values.chips.iter() {
                builder.assign(cumulative_sum, cumulative_sum + values.cumulative_sum);
            }
        }

        // Write all values to the public values struct and commit to them.
        {
            // Compute the vk digest.
            let vk_digest = vk.hash(builder);

            // Collect the public values for challengers.
            let initial_challenger_public_values =
                initial_reconstruct_challenger.public_values(builder);
            let final_challenger_public_values = reconstruct_challenger.public_values(builder);

            // Collect the cumulative sum.
            let cumulative_sum_array = builder.ext2felt_v2(cumulative_sum);

            // Collect the deferred proof digests.
            let zero: Felt<_> = builder.eval(C::F::zero());
            let start_deferred_digest = [zero; POSEIDON_NUM_WORDS];
            let end_deferred_digest = [zero; POSEIDON_NUM_WORDS];

            // Collect the is_complete flag.
            // let is_complete_felt = var2felt(builder, is_complete);

            // Initialize the public values we will commit to.
            let mut recursion_public_values_stream = [zero; RECURSIVE_PROOF_NUM_PV_ELTS];
            let recursion_public_values: &mut RecursionPublicValues<_> =
                recursion_public_values_stream.as_mut_slice().borrow_mut();
            recursion_public_values.committed_value_digest = committed_value_digest;
            recursion_public_values.deferred_proofs_digest = deferred_proofs_digest;
            recursion_public_values.start_pc = start_pc;
            recursion_public_values.next_pc = current_pc;
            recursion_public_values.start_shard = initial_shard;
            recursion_public_values.next_shard = current_shard;
            recursion_public_values.start_execution_shard = initial_execution_shard;
            recursion_public_values.next_execution_shard = current_execution_shard;
            recursion_public_values.previous_init_addr_bits = initial_previous_init_addr_bits;
            recursion_public_values.last_init_addr_bits = current_init_addr_bits;
            recursion_public_values.previous_finalize_addr_bits =
                initial_previous_finalize_addr_bits;
            recursion_public_values.last_finalize_addr_bits = current_finalize_addr_bits;
            recursion_public_values.sp1_vk_digest = vk_digest;
            recursion_public_values.leaf_challenger = leaf_challenger_public_values;
            recursion_public_values.start_reconstruct_challenger = initial_challenger_public_values;
            recursion_public_values.end_reconstruct_challenger = final_challenger_public_values;
            recursion_public_values.cumulative_sum = cumulative_sum_array;
            recursion_public_values.start_reconstruct_deferred_digest = start_deferred_digest;
            recursion_public_values.end_reconstruct_deferred_digest = end_deferred_digest;
            recursion_public_values.exit_code = exit_code;
            recursion_public_values.is_complete = is_complete;

            // // If the proof represents a complete proof, make completeness assertions.
            // //
            // // *Remark*: In this program, this only happends if there is one shard and the
            // program has // no deferred proofs to verify. However, the completeness
            // check is independent of these // facts.
            // builder.if_eq(is_complete, C::N::one()).then(|builder| {
            //     assert_complete(builder, recursion_public_values, &reconstruct_challenger)
            // });

            commit_recursion_public_values(builder, recursion_public_values);
        }
    }
}
