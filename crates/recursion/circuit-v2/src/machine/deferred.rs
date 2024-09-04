use std::{
    array,
    borrow::{Borrow, BorrowMut},
};

use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_commit::Mmcs;
use p3_field::AbstractField;
use p3_matrix::dense::RowMajorMatrix;

use sp1_primitives::consts::WORD_SIZE;
use sp1_recursion_compiler::ir::{Builder, Ext, Felt};

use sp1_stark::{
    air::{MachineAir, POSEIDON_NUM_WORDS},
    ShardProof, StarkGenericConfig, StarkMachine, StarkVerifyingKey, Word,
};

use sp1_recursion_core_v2::{
    air::{RecursionPublicValues, PV_DIGEST_NUM_WORDS, RECURSIVE_PROOF_NUM_PV_ELTS},
    DIGEST_SIZE,
};

use crate::{
    challenger::{CanObserveVariable, DuplexChallengerVariable},
    constraints::RecursiveVerifierConstraintFolder,
    stark::{ShardProofVariable, StarkVerifier},
    BabyBearFriConfigVariable, CircuitConfig, VerifyingKeyVariable,
};

pub struct SP1DeferredVerifier<C, SC, A> {
    _phantom: std::marker::PhantomData<(C, SC, A)>,
}

pub struct SP1DeferredWitnessValues<SC: StarkGenericConfig> {
    pub vks_and_proofs: Vec<(StarkVerifyingKey<SC>, ShardProof<SC>)>,
    pub start_reconstruct_deferred_digest: [SC::Val; POSEIDON_NUM_WORDS],
    pub sp1_vk: StarkVerifyingKey<SC>,
    pub leaf_challenger: SC::Challenger,
    pub committed_value_digest: [Word<SC::Val>; PV_DIGEST_NUM_WORDS],
    pub deferred_proofs_digest: [SC::Val; POSEIDON_NUM_WORDS],
    pub end_pc: SC::Val,
    pub end_shard: SC::Val,
    pub end_execution_shard: SC::Val,
    pub init_addr_bits: [SC::Val; 32],
    pub finalize_addr_bits: [SC::Val; 32],
    pub is_complete: bool,
}

pub struct SP1DeferredWitnessVariable<
    C: CircuitConfig<F = BabyBear>,
    SC: BabyBearFriConfigVariable<C>,
> {
    pub vks_and_proofs: Vec<(VerifyingKeyVariable<C, SC>, ShardProofVariable<C, SC>)>,
    pub start_reconstruct_deferred_digest: [Felt<C::F>; POSEIDON_NUM_WORDS],
    pub sp1_vk: VerifyingKeyVariable<C, SC>,
    pub leaf_challenger: SC::FriChallengerVariable,
    pub committed_value_digest: [Word<Felt<C::F>>; PV_DIGEST_NUM_WORDS],
    pub deferred_proofs_digest: [Felt<C::F>; POSEIDON_NUM_WORDS],
    pub end_pc: Felt<C::F>,
    pub end_shard: Felt<C::F>,
    pub end_execution_shard: Felt<C::F>,
    pub init_addr_bits: [Felt<C::F>; 32],
    pub finalize_addr_bits: [Felt<C::F>; 32],
    pub is_complete: Felt<C::F>,
}

impl<C, SC, A> SP1DeferredVerifier<C, SC, A>
where
    SC: BabyBearFriConfigVariable<
        C,
        FriChallengerVariable = DuplexChallengerVariable<C>,
        DigestVariable = [Felt<BabyBear>; DIGEST_SIZE],
    >,
    C: CircuitConfig<F = SC::Val, EF = SC::Challenge, Bit = Felt<BabyBear>>,
    <SC::ValMmcs as Mmcs<BabyBear>>::ProverData<RowMajorMatrix<BabyBear>>: Clone,
    A: MachineAir<SC::Val> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
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
        machine: &StarkMachine<SC, A>,
        input: SP1DeferredWitnessVariable<C, SC>,
    ) {
        let SP1DeferredWitnessVariable {
            vks_and_proofs,
            start_reconstruct_deferred_digest,
            sp1_vk,
            leaf_challenger,
            committed_value_digest,
            deferred_proofs_digest,
            end_pc,
            end_shard,
            end_execution_shard,
            init_addr_bits,
            finalize_addr_bits,
            is_complete,
        } = input;

        let mut deferred_public_values_stream: Vec<Felt<C::F>> =
            (0..RECURSIVE_PROOF_NUM_PV_ELTS).map(|_| builder.uninit()).collect();
        let deferred_public_values: &mut RecursionPublicValues<_> =
            deferred_public_values_stream.as_mut_slice().borrow_mut();

        // Initialize the start of deferred digests.
        deferred_public_values.start_reconstruct_deferred_digest =
            start_reconstruct_deferred_digest;

        // Initialize the consistency check variable.
        let mut reconstruct_deferred_digest: [Felt<C::F>; POSEIDON_NUM_WORDS] =
            start_reconstruct_deferred_digest;

        for (vk, shard_proof) in vks_and_proofs {
            // Initialize a challenger.
            let mut challenger = machine.config().challenger_variable(builder);
            // Observe the vk and start pc.
            challenger.observe(builder, vk.commitment);
            challenger.observe(builder, vk.pc_start);
            let zero: Felt<_> = builder.eval(C::F::zero());
            for _ in 0..7 {
                challenger.observe(builder, zero);
            }

            // Observe the and public values.
            challenger.observe_slice(
                builder,
                shard_proof.public_values[0..machine.num_pv_elts()].iter().copied(),
            );

            assert!(!shard_proof.contains_global_main_commitment());

            let zero_ext: Ext<C::F, C::EF> = builder.eval(C::F::zero());
            StarkVerifier::verify_shard(
                builder,
                &vk,
                machine,
                &mut challenger,
                &shard_proof,
                &[zero_ext, zero_ext],
            );

            // Get the current public values.
            let current_public_values: &RecursionPublicValues<Felt<C::F>> =
                shard_proof.public_values.as_slice().borrow();

            // Assert that the proof is complete.
            builder.assert_felt_eq(current_public_values.is_complete, C::F::one());

            // Update deferred proof digest
            // poseidon2( current_digest[..8] || pv.sp1_vk_digest[..8] ||
            // pv.committed_value_digest[..32] )
            let mut inputs: [Felt<C::F>; 48] = array::from_fn(|_| builder.uninit());
            inputs[0..DIGEST_SIZE].copy_from_slice(&reconstruct_deferred_digest);

            inputs[DIGEST_SIZE..DIGEST_SIZE + DIGEST_SIZE]
                .copy_from_slice(&current_public_values.sp1_vk_digest);

            for j in 0..PV_DIGEST_NUM_WORDS {
                for k in 0..WORD_SIZE {
                    let element = current_public_values.committed_value_digest[j][k];
                    inputs[j * WORD_SIZE + k + 16] = element;
                }
            }
            reconstruct_deferred_digest = SC::hash(builder, &inputs);
        }

        // Set the public values.

        // Set initial_pc, end_pc, initial_shard, and end_shard to be the hitned values.
        deferred_public_values.start_pc = end_pc;
        deferred_public_values.next_pc = end_pc;
        deferred_public_values.start_shard = end_shard;
        deferred_public_values.next_shard = end_shard;
        deferred_public_values.start_execution_shard = end_execution_shard;
        deferred_public_values.next_execution_shard = end_execution_shard;
        // Set the init and finalize address bits to be the hinted values.
        deferred_public_values.previous_init_addr_bits = init_addr_bits;
        deferred_public_values.last_init_addr_bits = init_addr_bits;
        deferred_public_values.previous_finalize_addr_bits = finalize_addr_bits;
        deferred_public_values.last_finalize_addr_bits = finalize_addr_bits;

        // Set the sp1_vk_digest to be the hitned value.
        deferred_public_values.sp1_vk_digest = sp1_vk.hash(builder);

        // Set the committed value digest to be the hitned value.
        deferred_public_values.committed_value_digest = committed_value_digest;
        // Set the deferred proof digest to be the hitned value.
        deferred_public_values.deferred_proofs_digest = deferred_proofs_digest;

        // Set the initial, end, and leaf challenger to be the hitned values.
        let values = leaf_challenger.public_values(builder);
        deferred_public_values.leaf_challenger = values;
        deferred_public_values.start_reconstruct_challenger = values;
        deferred_public_values.end_reconstruct_challenger = values;
        // Set the exit code to be zero for now.
        deferred_public_values.exit_code = builder.eval(C::F::zero());
        // Set the compress vk digest to be zero for now.
        deferred_public_values.compress_vk_digest = array::from_fn(|_| builder.eval(C::F::zero()));

        // Assign the deffered proof digests.
        deferred_public_values.end_reconstruct_deferred_digest = reconstruct_deferred_digest;

        // Set the is_complete flag.
        deferred_public_values.is_complete = is_complete;

        // TODO: set the digest according to the previous values.
        deferred_public_values.digest = array::from_fn(|_| builder.eval(C::F::zero()));

        // Set the cumulative sum to zero.
        deferred_public_values.cumulative_sum = array::from_fn(|_| builder.eval(C::F::zero()));

        SC::commit_recursion_public_values(builder, *deferred_public_values);
    }
}
