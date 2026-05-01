use std::{
    array,
    borrow::{Borrow, BorrowMut},
};

use serde::{Deserialize, Serialize};
use slop_challenger::IopCtx;

use crate::machine::{
    assert_recursion_public_values_valid, SP1MerkleProofVerifier, SP1MerkleProofWitnessValues,
    SP1MerkleProofWitnessVariable, VkAndProof,
};
use slop_air::Air;
use slop_algebra::{AbstractField, PrimeField32};
use sp1_hypercube::{
    air::{MachineAir, ShardRange, POSEIDON_NUM_WORDS, PROOF_NONCE_NUM_WORDS},
    septic_curve::SepticCurve,
    septic_digest::SepticDigest,
    ShardProof,
};
use sp1_primitives::{SP1ExtensionField, SP1Field};
use sp1_recursion_compiler::ir::{Builder, Felt};

use sp1_recursion_executor::{
    RecursionPublicValues, DIGEST_SIZE, PV_DIGEST_NUM_WORDS, RECURSIVE_PROOF_NUM_PV_ELTS,
};

use crate::{
    challenger::{CanObserveVariable, DuplexChallengerVariable},
    hash::{FieldHasher, FieldHasherVariable},
    shard::{MachineVerifyingKeyVariable, RecursiveShardVerifier, ShardProofVariable},
    zerocheck::RecursiveVerifierConstraintFolder,
    CircuitConfig, SP1FieldConfigVariable,
};

use super::{assert_complete, recursion_public_values_digest};

pub struct SP1DeferredVerifier<GC, C, A> {
    _phantom: std::marker::PhantomData<(GC, C, A)>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "GC::Challenger: Serialize, ShardProof<GC, Proof>: Serialize, [GC::F; DIGEST_SIZE]: Serialize"
))]
#[serde(bound(
    deserialize = "GC::Challenger: Deserialize<'de>, ShardProof<GC, Proof>: Deserialize<'de>,  [GC::F; DIGEST_SIZE]: Deserialize<'de>"
))]
pub struct SP1DeferredWitnessValues<
    GC: IopCtx<F = SP1Field, EF = SP1ExtensionField> + FieldHasher,
    Proof,
> {
    pub vks_and_proofs: Vec<VkAndProof<GC, Proof>>,
    pub vk_merkle_data: SP1MerkleProofWitnessValues<GC>,
    pub start_reconstruct_deferred_digest: [GC::F; POSEIDON_NUM_WORDS],
    pub sp1_vk_digest: [GC::F; DIGEST_SIZE],
    pub end_pc: [GC::F; 3],
    pub proof_nonce: [GC::F; PROOF_NONCE_NUM_WORDS],
    pub deferred_proof_index: GC::F,
}

impl<GC: IopCtx<F = SP1Field, EF = SP1ExtensionField> + FieldHasher, Proof>
    SP1DeferredWitnessValues<GC, Proof>
{
    /// The deferred proof range.
    ///
    /// The deferred proofs are put at the "start" and assigned initial and final timestamp equal to
    /// `1`. The rest of the range values are set to zero.
    pub fn range(&self) -> ShardRange {
        let prev_deferred_proof = self.deferred_proof_index.as_canonical_u32() as u64;
        let deferred_proof = prev_deferred_proof + self.vks_and_proofs.len() as u64;
        ShardRange {
            timestamp_range: (1, 1),
            initialized_address_range: (0, 0),
            finalized_address_range: (0, 0),
            initialized_page_index_range: (0, 0),
            finalized_page_index_range: (0, 0),
            deferred_proof_range: (prev_deferred_proof, deferred_proof),
        }
    }
}

#[allow(clippy::type_complexity)]
pub struct SP1DeferredWitnessVariable<
    C: CircuitConfig,
    SC: FieldHasherVariable<C> + SP1FieldConfigVariable<C>,
> {
    pub vks_and_proofs: Vec<(MachineVerifyingKeyVariable<C, SC>, ShardProofVariable<C, SC>)>,
    pub vk_merkle_data: SP1MerkleProofWitnessVariable<C, SC>,
    pub start_reconstruct_deferred_digest: [Felt<SP1Field>; POSEIDON_NUM_WORDS],
    pub sp1_vk_digest: [Felt<SP1Field>; DIGEST_SIZE],
    pub end_pc: [Felt<SP1Field>; 3],
    pub proof_nonce: [Felt<SP1Field>; PROOF_NONCE_NUM_WORDS],
    pub deferred_proof_index: Felt<SP1Field>,
}

impl<GC, C, A> SP1DeferredVerifier<GC, C, A>
where
    GC: IopCtx<F = SP1Field, EF = SP1ExtensionField>
        + SP1FieldConfigVariable<
            C,
            FriChallengerVariable = DuplexChallengerVariable<C>,
            DigestVariable = [Felt<SP1Field>; DIGEST_SIZE],
        > + Send
        + Sync,
    C: CircuitConfig,
    A: MachineAir<SP1Field> + for<'a> Air<RecursiveVerifierConstraintFolder<'a>>,
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
        machine: &RecursiveShardVerifier<GC, A, C>,
        input: SP1DeferredWitnessVariable<C, GC>,
        value_assertions: bool,
    ) {
        let SP1DeferredWitnessVariable {
            vks_and_proofs,
            vk_merkle_data,
            start_reconstruct_deferred_digest,
            sp1_vk_digest,
            end_pc,
            proof_nonce,
            deferred_proof_index,
        } = input;

        // First, verify the merkle tree proofs.
        let vk_root = vk_merkle_data.root;
        let values = vks_and_proofs.iter().map(|(vk, _)| vk.hash(builder)).collect::<Vec<_>>();
        SP1MerkleProofVerifier::verify(builder, values, vk_merkle_data, value_assertions);

        let mut deferred_public_values_stream: Vec<Felt<SP1Field>> =
            (0..RECURSIVE_PROOF_NUM_PV_ELTS).map(|_| builder.uninit()).collect();
        let deferred_public_values: &mut RecursionPublicValues<_> =
            deferred_public_values_stream.as_mut_slice().borrow_mut();

        // Initialize the start of deferred digests.
        deferred_public_values.start_reconstruct_deferred_digest =
            start_reconstruct_deferred_digest;

        // Initialize the consistency check variable.
        let mut reconstruct_deferred_digest: [Felt<SP1Field>; POSEIDON_NUM_WORDS] =
            start_reconstruct_deferred_digest;

        // Save the number of deferred proofs before consuming the vector.
        let num_deferred_proofs = SP1Field::from_canonical_usize(vks_and_proofs.len());

        for (vk, shard_proof) in vks_and_proofs {
            // Prepare a challenger.
            let mut challenger = GC::challenger_variable(builder);
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

            machine.verify_shard(builder, &vk, &shard_proof, &mut challenger);

            // Get the current public values.
            let current_public_values: &RecursionPublicValues<Felt<SP1Field>> =
                shard_proof.public_values.as_slice().borrow();
            // Assert that the `vk_root` is the same as the witnessed one.
            for (elem, expected) in current_public_values.vk_root.iter().zip(vk_root.iter()) {
                builder.assert_felt_eq(*elem, *expected);
            }
            // Assert that the public values are valid.
            assert_recursion_public_values_valid::<C, GC>(builder, current_public_values);

            // Assert that the proof is complete.
            builder.assert_felt_eq(current_public_values.is_complete, SP1Field::one());
            // Assert that the proof has `exit_code == 0`.
            builder.assert_felt_eq(current_public_values.exit_code, SP1Field::zero());

            // Update deferred proof digest
            // poseidon2( current_digest[..8] || pv.sp1_vk_digest[..8] ||
            // pv.committed_value_digest[..32] )
            let mut inputs: [Felt<SP1Field>; 48] = array::from_fn(|_| builder.uninit());
            inputs[0..DIGEST_SIZE].copy_from_slice(&reconstruct_deferred_digest);

            inputs[DIGEST_SIZE..DIGEST_SIZE + DIGEST_SIZE]
                .copy_from_slice(&current_public_values.sp1_vk_digest);

            for j in 0..PV_DIGEST_NUM_WORDS {
                for k in 0..4 {
                    let element = current_public_values.committed_value_digest[j][k];
                    inputs[j * 4 + k + 16] = element;
                }
            }
            reconstruct_deferred_digest = GC::hash(builder, &inputs);
        }

        // Set the public values.

        let zero = builder.eval(SP1Field::zero());
        let one = builder.eval(SP1Field::one());

        // Set initial_pc, end_pc, initial_shard, and end_shard to be the hinted values.
        deferred_public_values.pc_start = end_pc;
        deferred_public_values.next_pc = end_pc;
        // Set the init and finalize addresss to be the hinted values.
        deferred_public_values.previous_init_addr = core::array::from_fn(|_| zero);
        deferred_public_values.last_init_addr = core::array::from_fn(|_| zero);
        deferred_public_values.previous_finalize_addr = core::array::from_fn(|_| zero);
        deferred_public_values.last_finalize_addr = core::array::from_fn(|_| zero);
        // Set the init and finalize page index to be the hinted values.
        deferred_public_values.previous_init_page_idx = core::array::from_fn(|_| zero);
        deferred_public_values.last_init_page_idx = core::array::from_fn(|_| zero);
        deferred_public_values.previous_finalize_page_idx = core::array::from_fn(|_| zero);
        deferred_public_values.last_finalize_page_idx = core::array::from_fn(|_| zero);
        deferred_public_values.initial_timestamp = [zero, zero, zero, one];
        deferred_public_values.last_timestamp = [zero, zero, zero, one];

        // Set the sp1_vk_digest to be the hitned value.
        deferred_public_values.sp1_vk_digest = sp1_vk_digest;

        // Set the committed value digest to be the hitned value.
        deferred_public_values.prev_committed_value_digest =
            core::array::from_fn(|_| [zero, zero, zero, zero]);
        deferred_public_values.committed_value_digest =
            core::array::from_fn(|_| [zero, zero, zero, zero]);
        // Set the deferred proof digest to all zeroes.
        deferred_public_values.prev_deferred_proofs_digest = core::array::from_fn(|_| zero);
        deferred_public_values.deferred_proofs_digest = core::array::from_fn(|_| zero);

        // Set the exit code to be zero for now.
        deferred_public_values.prev_exit_code = zero;
        deferred_public_values.exit_code = zero;
        // Set the `commit_syscall` and `commit_deferred_syscall` flags to zero.
        deferred_public_values.prev_commit_syscall = zero;
        deferred_public_values.commit_syscall = zero;
        deferred_public_values.prev_commit_deferred_syscall = zero;
        deferred_public_values.commit_deferred_syscall = zero;
        // Assign the deferred proof digests.
        deferred_public_values.end_reconstruct_deferred_digest = reconstruct_deferred_digest;
        // Set the deferred proof index.
        deferred_public_values.prev_deferred_proof = deferred_proof_index;
        deferred_public_values.deferred_proof =
            builder.eval(deferred_proof_index + num_deferred_proofs);
        // Set the is_complete flag.
        deferred_public_values.is_complete = zero;
        deferred_public_values.proof_nonce = proof_nonce;
        // Set the cumulative sum to zero.
        deferred_public_values.global_cumulative_sum =
            SepticDigest(SepticCurve::convert(SepticDigest::<SP1Field>::zero().0, |value| {
                builder.eval(value)
            }));
        // Set the first shard flag to zero.
        deferred_public_values.contains_first_shard = zero;
        // Set the number of included shards to zero.
        deferred_public_values.num_included_shard = zero;
        // Set the vk root from the witness.
        deferred_public_values.vk_root = vk_root;
        // Set the digest according to the previous values.
        deferred_public_values.digest =
            recursion_public_values_digest::<C, GC>(builder, deferred_public_values);

        assert_complete(builder, deferred_public_values, deferred_public_values.is_complete);

        GC::commit_recursion_public_values(builder, *deferred_public_values);
    }
}
