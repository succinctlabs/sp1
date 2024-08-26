use std::{
    array,
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
};

use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{AbstractField, PrimeField32, TwoAdicField};
use sp1_core_machine::riscv::RiscvAir;
use sp1_primitives::{consts::WORD_SIZE, types::RecursionProgramType};
use sp1_recursion_compiler::{
    config::InnerConfig,
    ir::{Array, Builder, Config, Felt, Var},
    prelude::DslVariable,
};
use sp1_recursion_core::{
    air::{RecursionPublicValues, RECURSIVE_PROOF_NUM_PV_ELTS},
    runtime::{RecursionProgram, DIGEST_SIZE},
};

use sp1_recursion_compiler::prelude::*;
use sp1_stark::{
    air::{MachineAir, POSEIDON_NUM_WORDS, PV_DIGEST_NUM_WORDS},
    baby_bear_poseidon2::BabyBearPoseidon2,
    Com, ShardProof, StarkGenericConfig, StarkMachine, StarkVerifyingKey, Word,
};

use crate::{
    challenger::{CanObserveVariable, DuplexChallengerVariable},
    fri::TwoAdicFriPcsVariable,
    hints::Hintable,
    stark::{RecursiveVerifierConstraintFolder, StarkVerifier},
    types::{ShardProofVariable, VerifyingKeyVariable},
    utils::{const_fri_config, get_challenger_public_values, hash_vkey, var2felt},
};

use super::utils::{commit_public_values, verify_public_values_hash};

#[derive(Debug, Clone, Copy)]
pub struct SP1DeferredVerifier<C: Config, SC: StarkGenericConfig, A> {
    _phantom: PhantomData<(C, SC, A)>,
}

/// Inputs that are hinted to the [SP1DeferredVerifier] program.
pub struct SP1DeferredMemoryLayout<'a, SC: StarkGenericConfig, A: MachineAir<SC::Val>>
where
    SC::Val: PrimeField32,
{
    pub compress_vk: &'a StarkVerifyingKey<SC>,
    pub machine: &'a StarkMachine<SC, A>,
    pub proofs: Vec<ShardProof<SC>>,

    pub start_reconstruct_deferred_digest: Vec<SC::Val>,

    pub is_complete: bool,

    pub sp1_vk: &'a StarkVerifyingKey<SC>,
    pub sp1_machine: &'a StarkMachine<SC, RiscvAir<SC::Val>>,
    pub committed_value_digest: Vec<Word<SC::Val>>,
    pub deferred_proofs_digest: Vec<SC::Val>,
    pub leaf_challenger: SC::Challenger,
    pub end_pc: SC::Val,
    pub end_shard: SC::Val,
    pub end_execution_shard: SC::Val,
    pub init_addr_bits: [SC::Val; 32],
    pub finalize_addr_bits: [SC::Val; 32],
}

/// A variable version of the [SP1DeferredMemoryLayout] struct.
#[derive(DslVariable, Clone)]
pub struct SP1DeferredMemoryLayoutVariable<C: Config> {
    pub compress_vk: VerifyingKeyVariable<C>,

    pub proofs: Array<C, ShardProofVariable<C>>,

    pub start_reconstruct_deferred_digest: Array<C, Felt<C::F>>,

    pub is_complete: Var<C::N>,

    pub sp1_vk: VerifyingKeyVariable<C>,
    pub committed_value_digest: Array<C, Array<C, Felt<C::F>>>,
    pub deferred_proofs_digest: Array<C, Felt<C::F>>,
    pub leaf_challenger: DuplexChallengerVariable<C>,
    pub end_pc: Felt<C::F>,
    pub end_shard: Felt<C::F>,
    pub end_execution_shard: Felt<C::F>,
    pub init_addr_bits: Array<C, Felt<C::F>>,
    pub finalize_addr_bits: Array<C, Felt<C::F>>,
}

impl<A> SP1DeferredVerifier<InnerConfig, BabyBearPoseidon2, A>
where
    A: MachineAir<BabyBear> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, InnerConfig>>,
{
    /// Create a new instance of the program for the [BabyBearPoseidon2] config.
    pub fn build(machine: &StarkMachine<BabyBearPoseidon2, A>) -> RecursionProgram<BabyBear> {
        let mut builder = Builder::<InnerConfig>::new(RecursionProgramType::Deferred);
        let input: SP1DeferredMemoryLayoutVariable<_> = builder.uninit();
        SP1DeferredMemoryLayout::<BabyBearPoseidon2, A>::witness(&input, &mut builder);

        let pcs = TwoAdicFriPcsVariable {
            config: const_fri_config(&mut builder, machine.config().pcs().fri_config()),
        };

        SP1DeferredVerifier::verify(&mut builder, &pcs, machine, input);

        builder.halt();

        builder.compile_program()
    }
}

impl<C: Config, SC, A> SP1DeferredVerifier<C, SC, A>
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
    /// Verify a batch of deferred proofs.
    ///
    /// Each deferred proof is a recursive proof representing some computation. Namely, every such
    /// proof represents a recursively verified program.
    /// verifier:
    /// - Asserts that each of these proofs is valid as a `compress` proof.
    /// - Asserts that each of these proofs is complete by checking the `is_complete` flag in the
    ///   proof's public values.
    /// - Aggregates the proof information into the accumulated deferred digest.
    pub fn verify(
        builder: &mut Builder<C>,
        pcs: &TwoAdicFriPcsVariable<C>,
        machine: &StarkMachine<SC, A>,
        input: SP1DeferredMemoryLayoutVariable<C>,
    ) {
        // Read the inputs.
        let SP1DeferredMemoryLayoutVariable {
            compress_vk,
            proofs,
            start_reconstruct_deferred_digest,
            is_complete,
            sp1_vk,
            committed_value_digest,
            deferred_proofs_digest,
            leaf_challenger,
            end_pc,
            end_shard,
            end_execution_shard,
            init_addr_bits,
            finalize_addr_bits,
        } = input;

        // Initialize the values for the aggregated public output as all zeros.
        let mut deferred_public_values_stream: Vec<Felt<_>> =
            (0..RECURSIVE_PROOF_NUM_PV_ELTS).map(|_| builder.eval(C::F::zero())).collect();

        let deferred_public_values: &mut RecursionPublicValues<_> =
            deferred_public_values_stream.as_mut_slice().borrow_mut();

        // Compute the digest of compress_vk and input the value to the public values.
        let compress_vk_digest = hash_vkey(builder, &compress_vk);

        deferred_public_values.compress_vk_digest =
            array::from_fn(|i| builder.get(&compress_vk_digest, i));

        // Initialize the start of deferred digests.
        deferred_public_values.start_reconstruct_deferred_digest =
            array::from_fn(|i| builder.get(&start_reconstruct_deferred_digest, i));

        // Assert that there is at least one proof.
        builder.assert_usize_ne(proofs.len(), 0);

        // Initialize the consistency check variable.
        let mut reconstruct_deferred_digest = builder.array(POSEIDON_NUM_WORDS);
        for (i, first_digest) in
            deferred_public_values.start_reconstruct_deferred_digest.iter().enumerate()
        {
            builder.set(&mut reconstruct_deferred_digest, i, *first_digest);
        }

        // Verify the proofs and connect the values.
        builder.range(0, proofs.len()).for_each(|i, builder| {
            // Load the proof.
            let proof = builder.get(&proofs, i);

            // Verify the shard proof.

            // Prepare a challenger.
            let mut challenger = DuplexChallengerVariable::new(builder);
            // Observe the vk and start pc.
            challenger.observe(builder, compress_vk.commitment.clone());
            challenger.observe(builder, compress_vk.pc_start);
            // Observe the main commitment and public values.
            challenger.observe(builder, proof.commitment.main_commit.clone());
            for j in 0..machine.num_pv_elts() {
                let element = builder.get(&proof.public_values, j);
                challenger.observe(builder, element);
            }

            // Verify the proof.
            StarkVerifier::<C, SC>::verify_shard(
                builder,
                &compress_vk,
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

            // Assert that the proof is complete.
            builder.assert_felt_eq(current_public_values.is_complete, C::F::one());

            // Assert that the compress_vk digest is the same.
            for (digest, current) in deferred_public_values
                .compress_vk_digest
                .iter()
                .zip(current_public_values.compress_vk_digest.iter())
            {
                builder.assert_felt_eq(*digest, *current);
            }

            // Update deferred proof digest
            // poseidon2( current_digest[..8] || pv.sp1_vk_digest[..8] ||
            // pv.committed_value_digest[..32] )
            let mut poseidon_inputs = builder.array(48);
            for j in 0..DIGEST_SIZE {
                let current_digest_element = builder.get(&reconstruct_deferred_digest, j);
                builder.set(&mut poseidon_inputs, j, current_digest_element);
            }

            for j in 0..DIGEST_SIZE {
                // let input_index: Var<_> = builder.constant(F::from_canonical_usize(j + 8));
                builder.set(
                    &mut poseidon_inputs,
                    j + DIGEST_SIZE,
                    current_public_values.sp1_vk_digest[j],
                );
            }
            for j in 0..PV_DIGEST_NUM_WORDS {
                for k in 0..WORD_SIZE {
                    // let input_index: Var<_> =
                    //     builder.eval(F::from_canonical_usize(j * WORD_SIZE + k + 16));
                    let element = current_public_values.committed_value_digest[j][k];
                    builder.set(&mut poseidon_inputs, j * WORD_SIZE + k + 16, element);
                }
            }
            let new_digest = builder.poseidon2_hash(&poseidon_inputs);
            for j in 0..DIGEST_SIZE {
                let new_value = builder.get(&new_digest, j);
                builder.set(&mut reconstruct_deferred_digest, j, new_value);
            }
        });

        // Set the public values.

        // Set initial_pc, end_pc, initial_shard, and end_shard to be the hitned values.
        deferred_public_values.start_pc = end_pc;
        deferred_public_values.next_pc = end_pc;
        deferred_public_values.start_shard = end_shard;
        deferred_public_values.next_shard = end_shard;
        deferred_public_values.start_execution_shard = end_execution_shard;
        deferred_public_values.next_execution_shard = end_execution_shard;
        // Set the init and finalize address bits to be the hintred values.
        let init_addr_bits = core::array::from_fn(|i| builder.get(&init_addr_bits, i));
        deferred_public_values.previous_init_addr_bits = init_addr_bits;
        deferred_public_values.last_init_addr_bits = init_addr_bits;
        let finalize_addr_bits = core::array::from_fn(|i| builder.get(&finalize_addr_bits, i));
        deferred_public_values.previous_finalize_addr_bits = finalize_addr_bits;
        deferred_public_values.last_finalize_addr_bits = finalize_addr_bits;

        // Set the sp1_vk_digest to be the hitned value.
        let sp1_vk_digest = hash_vkey(builder, &sp1_vk);
        deferred_public_values.sp1_vk_digest = array::from_fn(|i| builder.get(&sp1_vk_digest, i));

        // Set the committed value digest to be the hitned value.
        for (i, public_word) in deferred_public_values.committed_value_digest.iter_mut().enumerate()
        {
            let hinted_word = builder.get(&committed_value_digest, i);
            public_word.0 = array::from_fn(|j| builder.get(&hinted_word, j));
        }

        // Set the deferred proof digest to be the hitned value.
        deferred_public_values.deferred_proofs_digest =
            core::array::from_fn(|i| builder.get(&deferred_proofs_digest, i));

        // Set the initial, end, and leaf challenger to be the hitned values.
        let values = get_challenger_public_values(builder, &leaf_challenger);
        deferred_public_values.leaf_challenger = values;
        deferred_public_values.start_reconstruct_challenger = values;
        deferred_public_values.end_reconstruct_challenger = values;

        // Assign the deffered proof digests.
        deferred_public_values.end_reconstruct_deferred_digest =
            array::from_fn(|i| builder.get(&reconstruct_deferred_digest, i));

        // Set the is_complete flag.
        deferred_public_values.is_complete = var2felt(builder, is_complete);

        commit_public_values(builder, deferred_public_values);
    }
}
