use crate::machine::SP1ShapedWitnessValues;
use std::marker::PhantomData;

use super::SP1ShapedWitnessVariable;
use crate::{
    basefold::merkle_tree::verify, hash::FieldHasher, CircuitConfig, FieldHasherVariable,
    SP1FieldConfigVariable,
};
use serde::{Deserialize, Serialize};
use slop_algebra::AbstractField;
use sp1_hypercube::MerkleProof;
use sp1_primitives::{SP1Field, SP1GlobalContext};
use sp1_recursion_compiler::ir::Builder;
use sp1_recursion_executor::DIGEST_SIZE;

/// A program to verify a batch of recursive proofs and aggregate their public values.
#[derive(Debug, Clone, Copy)]
pub struct SP1MerkleProofVerifier<C, SC> {
    _phantom: PhantomData<(C, SC)>,
}

#[derive(Clone)]
pub struct MerkleProofVariable<C: CircuitConfig, HV: FieldHasherVariable<C>> {
    pub index: Vec<C::Bit>,
    pub path: Vec<HV::DigestVariable>,
}

/// Witness layout for the compress stage verifier.
pub struct SP1MerkleProofWitnessVariable<
    C: CircuitConfig,
    SC: FieldHasherVariable<C> + SP1FieldConfigVariable<C>,
> {
    /// The shard proofs to verify.
    pub vk_merkle_proofs: Vec<MerkleProofVariable<C, SC>>,
    /// Hinted values to enable dummy digests.
    pub values: Vec<SC::DigestVariable>,
    /// The root of the merkle tree.
    pub root: SC::DigestVariable,
}

/// An input layout for the reduce verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "GC::Digest: Serialize"))]
#[serde(bound(deserialize = "GC::Digest: Deserialize<'de>"))]
pub struct SP1MerkleProofWitnessValues<GC: FieldHasher> {
    pub vk_merkle_proofs: Vec<MerkleProof<GC>>,
    pub values: Vec<GC::Digest>,
    pub root: GC::Digest,
}

impl<C, SC> SP1MerkleProofVerifier<C, SC>
where
    SC: SP1FieldConfigVariable<C>,
    C: CircuitConfig,
{
    /// Verify (via Merkle tree) that the vkey digests of a proof belong to a specified set
    /// (encoded the Merkle tree proofs in input).
    pub fn verify(
        builder: &mut Builder<C>,
        digests: Vec<SC::DigestVariable>,
        input: SP1MerkleProofWitnessVariable<C, SC>,
        value_assertions: bool,
    ) {
        let SP1MerkleProofWitnessVariable { vk_merkle_proofs, values, root } = input;
        for ((proof, value), expected_value) in
            vk_merkle_proofs.into_iter().zip(values).zip(digests)
        {
            verify::<C, SC>(builder, proof.path, proof.index, value, root);
            if value_assertions {
                SC::assert_digest_eq(builder, expected_value, value);
            } else {
                SC::assert_digest_eq(builder, value, value);
            }
        }
    }
}

/// Witness layout for the verifier of the proof shape phase of the compress stage.
pub struct SP1CompressWithVKeyWitnessVariable<C: CircuitConfig, GC: SP1FieldConfigVariable<C>> {
    pub compress_var: SP1ShapedWitnessVariable<C, GC>,
    pub merkle_var: SP1MerkleProofWitnessVariable<C, GC>,
}

/// An input layout for the verifier of the proof shape phase of the compress stage.
#[derive(Serialize, Deserialize)]
pub struct SP1CompressWithVKeyWitnessValues<Proof> {
    pub compress_val: SP1ShapedWitnessValues<SP1GlobalContext, Proof>,
    pub merkle_val: SP1MerkleProofWitnessValues<SP1GlobalContext>,
}

impl SP1MerkleProofWitnessValues<SP1GlobalContext> {
    pub fn dummy(num_proofs: usize, height: usize) -> Self {
        let dummy_digest = [SP1Field::zero(); DIGEST_SIZE];
        let vk_merkle_proofs =
            vec![MerkleProof { index: 0, path: vec![dummy_digest; height] }; num_proofs];
        let values = vec![dummy_digest; num_proofs];

        Self { vk_merkle_proofs, values, root: dummy_digest }
    }
}
