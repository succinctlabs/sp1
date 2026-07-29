use crate::{
    hash::FieldHasher,
    machine::{
        MerkleProofVariable, SP1CompressWithVKeyWitnessValues, SP1CompressWithVKeyWitnessVariable,
        SP1MerkleProofWitnessValues, SP1MerkleProofWitnessVariable, SP1ShapedWitnessVariable,
    },
};
use slop_algebra::AbstractField;
use slop_challenger::{DuplexChallenger, IopCtx};
use slop_symmetric::Hash;
use sp1_primitives::{SP1Field, SP1GlobalContext, SP1Perm};
use std::{borrow::Borrow, marker::PhantomData};

use super::{
    InnerVal, SP1DeferredWitnessValues, SP1DeferredWitnessVariable, SP1NormalizeWitnessValues,
    SP1RecursionWitnessVariable, SP1ShapedWitnessValues,
};
use crate::{
    basefold::RecursiveBasefoldVerifier,
    challenger::DuplexChallengerVariable,
    hash::FieldHasherVariable,
    jagged::RecursivePcsImpl,
    shard::{MachineVerifyingKeyVariable, ShardProofVariable},
    witness::{WitnessWriter, Witnessable},
    CircuitConfig, SP1FieldConfigVariable,
};
use sp1_hypercube::{MachineVerifyingKey, MerkleProof, SP1PcsProofInner, ShardProof, Word};
use sp1_recursion_compiler::{
    config::InnerConfig,
    ir::{Builder, Felt},
};

impl<C: CircuitConfig, T: Witnessable<C>> Witnessable<C> for Word<T> {
    type WitnessVariable = Word<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        Word(self.0.read(builder))
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.0.write(witness);
    }
}

impl<C> Witnessable<C> for DuplexChallenger<SP1Field, SP1Perm, 16, 8>
where
    C: CircuitConfig,
{
    type WitnessVariable = DuplexChallengerVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let sponge_state = self.sponge_state.read(builder);
        let input_buffer = self.input_buffer.read(builder);
        let output_buffer = self.output_buffer.read(builder);
        DuplexChallengerVariable { sponge_state, input_buffer, output_buffer, marker: PhantomData }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.sponge_state.write(witness);
        self.input_buffer.write(witness);
        self.output_buffer.write(witness);
    }
}

impl<C, F, W, const DIGEST_ELEMENTS: usize> Witnessable<C> for Hash<F, W, DIGEST_ELEMENTS>
where
    C: CircuitConfig,
    W: Witnessable<C>,
{
    type WitnessVariable = [W::WitnessVariable; DIGEST_ELEMENTS];

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let array: &[W; DIGEST_ELEMENTS] = self.borrow();
        array.read(builder)
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        let array: &[W; DIGEST_ELEMENTS] = self.borrow();
        array.write(witness);
    }
}

pub type JC<C, SC> = RecursivePcsImpl<C, SC, RecursiveBasefoldVerifier<C, SC>>;

impl Witnessable<InnerConfig> for SP1NormalizeWitnessValues<SP1GlobalContext, SP1PcsProofInner> {
    type WitnessVariable = SP1RecursionWitnessVariable<InnerConfig, SP1GlobalContext>;

    fn read(&self, builder: &mut Builder<InnerConfig>) -> Self::WitnessVariable {
        let vk = self.vk.read(builder);
        let shard_proofs = self.shard_proofs.read(builder);
        let reconstruct_deferred_digest = self.reconstruct_deferred_digest.read(builder);
        let vk_root = self.vk_root.read(builder);
        let num_deferred_proofs = self.num_deferred_proofs.read(builder);
        let commitments_hash = self.commitments_hash.read(builder);
        let prev_hasher_state = self.prev_hasher_state.read(builder);
        SP1RecursionWitnessVariable {
            vk,
            shard_proofs,
            reconstruct_deferred_digest,
            vk_root,
            num_deferred_proofs,
            commitments_hash,
            prev_hasher_state,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<InnerConfig>) {
        self.vk.write(witness);
        self.shard_proofs.write(witness);
        self.reconstruct_deferred_digest.write(witness);
        self.vk_root.write(witness);
        self.num_deferred_proofs.write(witness);
        self.commitments_hash.write(witness);
        self.prev_hasher_state.write(witness);
    }
}

impl<GC: IopCtx + SP1FieldConfigVariable<C>, C: CircuitConfig, Proof> Witnessable<C>
    for SP1ShapedWitnessValues<GC, Proof>
where
    MachineVerifyingKey<GC>: Witnessable<C, WitnessVariable = MachineVerifyingKeyVariable<C, GC>>,
    ShardProof<GC, Proof>: Witnessable<C, WitnessVariable = ShardProofVariable<C, GC>>,
{
    type WitnessVariable = SP1ShapedWitnessVariable<C, GC>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let vks_and_proofs = self.vks_and_proofs.read(builder);
        let is_complete = InnerVal::from_bool(self.is_complete).read(builder);

        SP1ShapedWitnessVariable { vks_and_proofs, is_complete }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.vks_and_proofs.write(witness);
        InnerVal::from_bool(self.is_complete).write(witness);
    }
}

impl<C> Witnessable<C> for SP1DeferredWitnessValues<SP1GlobalContext, SP1PcsProofInner>
where
    C: CircuitConfig<Bit = Felt<InnerVal>>,
{
    type WitnessVariable = SP1DeferredWitnessVariable<C, SP1GlobalContext>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let vks_and_proofs = self.vks_and_proofs.read(builder);
        let vk_merkle_data = self.vk_merkle_data.read(builder);
        let start_reconstruct_deferred_digest =
            self.start_reconstruct_deferred_digest.read(builder);
        let sp1_vk_digest = self.sp1_vk_digest.read(builder);
        let end_pc = self.end_pc.read(builder);
        let initial_memory_root = self.initial_memory_root.read(builder);
        let proof_nonce = self.proof_nonce.read(builder);
        let deferred_proof_index = self.deferred_proof_index.read(builder);

        SP1DeferredWitnessVariable {
            vks_and_proofs,
            vk_merkle_data,
            start_reconstruct_deferred_digest,
            sp1_vk_digest,
            end_pc,
            initial_memory_root,
            proof_nonce,
            deferred_proof_index,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.vks_and_proofs.write(witness);
        self.vk_merkle_data.write(witness);
        self.start_reconstruct_deferred_digest.write(witness);
        self.sp1_vk_digest.write(witness);
        self.end_pc.write(witness);
        self.initial_memory_root.write(witness);
        self.proof_nonce.write(witness);
        self.deferred_proof_index.write(witness);
    }
}

impl<C: CircuitConfig, HV: FieldHasherVariable<C>> Witnessable<C> for MerkleProof<HV>
where
    HV::Digest: Witnessable<C, WitnessVariable = HV::DigestVariable>,
{
    type WitnessVariable = MerkleProofVariable<C, HV>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let mut bits = vec![];
        let mut index = self.index;
        for _ in 0..self.path.len() {
            bits.push(index % 2 == 1);
            index >>= 1;
        }
        bits.reverse();
        let index_bits = bits.read(builder);
        let path = self.path.read(builder);

        MerkleProofVariable { index: index_bits, path }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        let mut index = self.index;
        let mut bits: Vec<bool> = vec![];
        for _ in 0..self.path.len() {
            bits.push(index % 2 == 1);
            index >>= 1;
        }
        bits.reverse();
        for bit in bits.iter() {
            bit.write(witness);
        }
        self.path.write(witness);
    }
}

impl<C: CircuitConfig, SC: SP1FieldConfigVariable<C>> Witnessable<C>
    for SP1MerkleProofWitnessValues<SC>
where
    // This trait bound is redundant, but Rust-Analyzer is not able to infer it.
    SC: FieldHasher<F = SP1Field>,
    <SC as IopCtx>::Digest: Witnessable<C, WitnessVariable = SC::DigestVariable>,
{
    type WitnessVariable = SP1MerkleProofWitnessVariable<C, SC>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        SP1MerkleProofWitnessVariable {
            vk_merkle_proofs: self.vk_merkle_proofs.read(builder),
            values: self.values.read(builder),
            root: self.root.read(builder),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.vk_merkle_proofs.write(witness);
        self.values.write(witness);
        self.root.write(witness);
    }
}

impl<C: CircuitConfig, Proof> Witnessable<C> for SP1CompressWithVKeyWitnessValues<Proof>
where
    <SP1GlobalContext as IopCtx>::Digest: Witnessable<
        C,
        WitnessVariable = <SP1GlobalContext as FieldHasherVariable<C>>::DigestVariable,
    >,
    MachineVerifyingKey<SP1GlobalContext>:
        Witnessable<C, WitnessVariable = MachineVerifyingKeyVariable<C, SP1GlobalContext>>,
    ShardProof<SP1GlobalContext, Proof>:
        Witnessable<C, WitnessVariable = ShardProofVariable<C, SP1GlobalContext>>,
    SP1GlobalContext: SP1FieldConfigVariable<C>,
{
    type WitnessVariable = SP1CompressWithVKeyWitnessVariable<C, SP1GlobalContext>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        SP1CompressWithVKeyWitnessVariable {
            compress_var: self.compress_val.read(builder),
            merkle_var: self.merkle_val.read(builder),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.compress_val.write(witness);
        self.merkle_val.write(witness);
    }
}
