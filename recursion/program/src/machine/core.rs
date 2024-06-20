use std::array;
use std::borrow::BorrowMut;
use std::marker::PhantomData;

use itertools::Itertools;
use p3_baby_bear::BabyBear;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{AbstractField, PrimeField32, TwoAdicField};
use sp1_core::air::{MachineAir, PublicValues};
use sp1_core::air::{Word, POSEIDON_NUM_WORDS, PV_DIGEST_NUM_WORDS};
use sp1_core::stark::StarkMachine;
use sp1_core::stark::{Com, RiscvAir, ShardProof, StarkGenericConfig, StarkVerifyingKey};
use sp1_core::utils::BabyBearPoseidon2;
use sp1_recursion_compiler::config::InnerConfig;
use sp1_recursion_compiler::ir::{Array, Builder, Config, Ext, ExtConst, Felt, Var};
use sp1_recursion_compiler::prelude::DslVariable;
use sp1_recursion_core::air::{RecursionPublicValues, RECURSIVE_PROOF_NUM_PV_ELTS};
use sp1_recursion_core::runtime::{RecursionProgram, DIGEST_SIZE};

use sp1_recursion_compiler::prelude::*;

use crate::challenger::{CanObserveVariable, DuplexChallengerVariable};
use crate::fri::TwoAdicFriPcsVariable;
use crate::hints::Hintable;
use crate::stark::StarkVerifier;
use crate::types::ShardProofVariable;
use crate::types::VerifyingKeyVariable;
use crate::utils::{const_fri_config, felt2var, get_challenger_public_values, hash_vkey, var2felt};

use super::utils::{assert_complete, commit_public_values};

/// A program for recursively verifying a batch of SP1 proofs.
#[derive(Debug, Clone, Copy)]
pub struct SP1RecursiveVerifier<C: Config, SC: StarkGenericConfig> {
    _phantom: PhantomData<(C, SC)>,
}

pub struct SP1RecursionMemoryLayout<'a, SC: StarkGenericConfig, A: MachineAir<SC::Val>> {
    pub vk: &'a StarkVerifyingKey<SC>,
    pub machine: &'a StarkMachine<SC, A>,
    pub shard_proofs: Vec<ShardProof<SC>>,
    pub leaf_challenger: &'a SC::Challenger,
    pub initial_reconstruct_challenger: SC::Challenger,
    pub is_complete: bool,
    pub total_core_shards: usize,
}

#[derive(DslVariable, Clone)]
pub struct SP1RecursionMemoryLayoutVariable<C: Config> {
    pub vk: VerifyingKeyVariable<C>,

    pub shard_proofs: Array<C, ShardProofVariable<C>>,

    pub leaf_challenger: DuplexChallengerVariable<C>,
    pub initial_reconstruct_challenger: DuplexChallengerVariable<C>,

    pub is_complete: Var<C::N>,

    pub total_core_shards: Var<C::N>,
}

impl SP1RecursiveVerifier<InnerConfig, BabyBearPoseidon2> {
    /// Create a new instance of the program for the [BabyBearPoseidon2] config.
    pub fn build(
        machine: &StarkMachine<BabyBearPoseidon2, RiscvAir<BabyBear>>,
    ) -> RecursionProgram<BabyBear> {
        let mut builder = Builder::<InnerConfig>::default();

        let input: SP1RecursionMemoryLayoutVariable<_> = builder.uninit();
        SP1RecursionMemoryLayout::<BabyBearPoseidon2, RiscvAir<_>>::witness(&input, &mut builder);

        let pcs = TwoAdicFriPcsVariable {
            config: const_fri_config(&mut builder, machine.config().pcs().fri_config()),
        };
        SP1RecursiveVerifier::verify(&mut builder, &pcs, machine, input);

        builder.halt();

        builder.compile_program()
    }
}

impl<C: Config, SC: StarkGenericConfig> SP1RecursiveVerifier<C, SC>
where
    C::F: PrimeField32 + TwoAdicField,
    SC: StarkGenericConfig<
        Val = C::F,
        Challenge = C::EF,
        Domain = TwoAdicMultiplicativeCoset<C::F>,
    >,
    Com<SC>: Into<[SC::Val; DIGEST_SIZE]>,
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
    ///
    /// See [SP1Prover::verify] for the verification algorithm of a complete SP1 proof. In this
    /// function, we are aggregating several shard proofs and attesting to an aggregated state which
    /// reprersents all the shards. The consistency conditions of the aggregated state are
    /// asserted in the following way:
    ///
    /// - Start pc for every shardf should be what the next pc declared in the previous shard was.
    /// - Public input, deferred proof digests, and exit code should be the same in all shards.
    ///
    /// ## The leaf challenger.
    /// A key difference between the recursive tree verification and the complete one in
    /// [SP1Prover::verify] is that the recursive verifier has no way of reconstructiing the
    /// chanllenger only from a part of the shard proof. Therefoee, the value of the leaf challenger
    /// is witnessed in the program and the verifier assertds correctness given this challenger.
    /// In the course of the recursive verification, the challenger is reconstructed by observing
    /// the commitments one by one, and in the final step, the challenger is asserted to be the same
    /// as the one witnessed here.
    pub fn verify(
        builder: &mut Builder<C>,
        pcs: &TwoAdicFriPcsVariable<C>,
        machine: &StarkMachine<SC, RiscvAir<SC::Val>>,
        input: SP1RecursionMemoryLayoutVariable<C>,
    ) {
        // Read input.
        let SP1RecursionMemoryLayoutVariable {
            vk,
            shard_proofs,
            leaf_challenger,
            initial_reconstruct_challenger,
            is_complete,
            total_core_shards,
        } = input;

        // Initialize values we will commit to public outputs.

        // Start and end of program counters.
        let start_pc: Felt<_> = builder.uninit();

        // Start and end shard indices.
        let initial_shard: Felt<_> = builder.uninit();

        // The commited values digest and deferred proof digest. These will be checked to be the
        // same for all proofs.
        let committed_value_digest: [Word<Felt<_>>; PV_DIGEST_NUM_WORDS] =
            array::from_fn(|_| Word(array::from_fn(|_| builder.uninit())));
        let deferred_proofs_digest: [Felt<_>; POSEIDON_NUM_WORDS] =
            array::from_fn(|_| builder.uninit());

        // Assert that the number of proofs is not zero.
        builder.assert_usize_ne(shard_proofs.len(), 0);

        let leaf_challenger_public_values = get_challenger_public_values(builder, &leaf_challenger);

        // Initialize loop variables.
        let current_shard: Felt<_> = builder.uninit();
        let mut reconstruct_challenger: DuplexChallengerVariable<_> =
            initial_reconstruct_challenger.copy(builder);
        let cumulative_sum: Ext<_, _> = builder.eval(C::EF::zero().cons());
        let current_pc: Felt<_> = builder.uninit();
        let exit_code: Felt<_> = builder.uninit();

        // Range check that the number of proofs is sufficiently small.
        let num_shard_proofs: Var<_> = shard_proofs.len().materialize(builder);
        builder.range_check_v(num_shard_proofs, 16);

        // Verify proofs, validate transitions, and update accumulation variables.
        builder.range(0, shard_proofs.len()).for_each(|i, builder| {
            // Load the proof.
            let proof = builder.get(&shard_proofs, i);

            // Verify the shard proof.
            let mut challenger = leaf_challenger.copy(builder);
            StarkVerifier::<C, SC>::verify_shard(
                builder,
                &vk,
                pcs,
                machine,
                &mut challenger,
                &proof,
                total_core_shards,
            );

            // Extract public values.
            let mut pv_elements = Vec::new();
            for i in 0..machine.num_pv_elts() {
                let element = builder.get(&proof.public_values, i);
                pv_elements.push(element);
            }
            let public_values = PublicValues::<Word<Felt<_>>, Felt<_>>::from_vec(pv_elements);

            // If this is the first proof in the batch, verify the initial conditions.
            builder.if_eq(i, C::N::zero()).then(|builder| {
                // Initialize the values of accumulated variables.

                // Shard.
                builder.assign(initial_shard, public_values.shard);
                builder.assign(current_shard, public_values.shard);

                // Program counter.
                builder.assign(start_pc, public_values.start_pc);
                builder.assign(current_pc, public_values.start_pc);

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

                // Exit code.
                builder.assign(exit_code, public_values.exit_code);
            });

            // If it's first shard, verify the global initial conditions hold on challenger and pc.
            let shard = felt2var(builder, public_values.shard);
            builder.if_eq(shard, C::N::one()).then(|builder| {
                // This should be the 0th proof in this batch.
                builder.assert_var_eq(i, C::N::zero());

                // Start pc should be vk.pc_start
                builder.assert_felt_eq(public_values.start_pc, vk.pc_start);

                // Assert that the initial challenger is equal to a fresh challenger observing the
                // verifier key and the initial pc.
                let mut first_initial_challenger = DuplexChallengerVariable::new(builder);

                first_initial_challenger.observe(builder, vk.commitment.clone());
                first_initial_challenger.observe(builder, vk.pc_start);

                // Make sure the start reconstruct challenger is correct, since we will
                // commit to it in public values.
                initial_reconstruct_challenger.assert_eq(builder, &first_initial_challenger);
            });

            // Assert compatibility of the shard values.

            // Assert that the committed value digests are all the same.
            for (word, current_word) in committed_value_digest
                .iter()
                .zip_eq(public_values.committed_value_digest.iter())
            {
                for (byte, current_byte) in word.0.iter().zip_eq(current_word.0.iter()) {
                    builder.assert_felt_eq(*byte, *current_byte);
                }
            }

            // Assert that the start_pc of the proof is equal to the current pc.
            builder.assert_felt_eq(current_pc, public_values.start_pc);
            // Assert that the start_pc is not zero (this means program has halted in a non-last
            // shard).
            builder.assert_felt_ne(public_values.start_pc, C::F::zero());

            // Assert that the shard of the proof is equal to the current shard.
            builder.assert_felt_eq(current_shard, public_values.shard);

            // Assert that exit code is the same for all proofs.
            builder.assert_felt_eq(exit_code, public_values.exit_code);

            // Assert that the exit code is zero (success) for all proofs.
            builder.assert_felt_eq(exit_code, C::F::zero());

            // Assert that the deferred proof digest is the same for all proofs.
            for (digest, current_digest) in deferred_proofs_digest
                .iter()
                .zip_eq(public_values.deferred_proofs_digest.iter())
            {
                builder.assert_felt_eq(*digest, *current_digest);
            }

            // Update the loop variables: the reconstruct challenger, cumulative sum, shard number,
            // and program counter.

            // Increment the shard index by one.
            builder.assign(current_shard, current_shard + C::F::one());

            // Update the reconstruct challenger.
            reconstruct_challenger.observe(builder, proof.commitment.main_commit);
            for j in 0..machine.num_pv_elts() {
                let element = builder.get(&proof.public_values, j);
                reconstruct_challenger.observe(builder, element);
            }

            // Update current_pc to be the end_pc of the current proof.
            builder.assign(current_pc, public_values.next_pc);

            // Cumulative sum is updated by sums of all chips.
            let opened_values = proof.opened_values.chips;
            builder
                .range(0, opened_values.len())
                .for_each(|k, builder| {
                    let values = builder.get(&opened_values, k);
                    let sum = values.cumulative_sum;
                    builder.assign(cumulative_sum, cumulative_sum + sum);
                });
        });

        // Write all values to the public values struct and commit to them.

        // Compute vk digest.
        let vk_digest = hash_vkey(builder, &vk);
        let vk_digest: [Felt<_>; DIGEST_SIZE] = array::from_fn(|i| builder.get(&vk_digest, i));

        // Collect values for challenges.
        let initial_challenger_public_values =
            get_challenger_public_values(builder, &initial_reconstruct_challenger);
        let final_challenger_public_values =
            get_challenger_public_values(builder, &reconstruct_challenger);

        let cumulative_sum_arrray = builder.ext2felt(cumulative_sum);
        let cumulative_sum_arrray = array::from_fn(|i| builder.get(&cumulative_sum_arrray, i));

        let zero: Felt<_> = builder.eval(C::F::zero());

        // Initialize the public values we will commit to.
        let mut recursion_public_values_stream = [zero; RECURSIVE_PROOF_NUM_PV_ELTS];

        let recursion_public_values: &mut RecursionPublicValues<_> =
            recursion_public_values_stream.as_mut_slice().borrow_mut();

        let start_deferred_digest = [zero; POSEIDON_NUM_WORDS];
        let end_deferred_digest = [zero; POSEIDON_NUM_WORDS];

        let is_complete_felt = var2felt(builder, is_complete);
        let total_core_shards_felt = var2felt(builder, total_core_shards);

        recursion_public_values.committed_value_digest = committed_value_digest;
        recursion_public_values.deferred_proofs_digest = deferred_proofs_digest;
        recursion_public_values.start_pc = start_pc;
        recursion_public_values.next_pc = current_pc;
        recursion_public_values.start_shard = initial_shard;
        recursion_public_values.next_shard = current_shard;
        recursion_public_values.sp1_vk_digest = vk_digest;
        recursion_public_values.leaf_challenger = leaf_challenger_public_values;
        recursion_public_values.start_reconstruct_challenger = initial_challenger_public_values;
        recursion_public_values.end_reconstruct_challenger = final_challenger_public_values;
        recursion_public_values.cumulative_sum = cumulative_sum_arrray;
        recursion_public_values.start_reconstruct_deferred_digest = start_deferred_digest;
        recursion_public_values.end_reconstruct_deferred_digest = end_deferred_digest;
        recursion_public_values.is_complete = is_complete_felt;
        recursion_public_values.total_core_shards = total_core_shards_felt;

        // If the proof represents a complete proof, make completeness assertions.
        //
        // *Remark*: In this program, this only happends if there is one shard and the program has
        // no deferred proofs to verify. However, the completeness check is independent of these
        // facts.
        builder.if_eq(is_complete, C::N::one()).then(|builder| {
            assert_complete(builder, recursion_public_values, &reconstruct_challenger)
        });

        commit_public_values(builder, recursion_public_values);
    }
}
