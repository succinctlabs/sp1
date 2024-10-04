use std::marker::PhantomData;

use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_commit::Mmcs;
use p3_field::AbstractField;
use p3_matrix::dense::RowMajorMatrix;
use serde::{Deserialize, Serialize};
use sp1_recursion_compiler::ir::{Builder, Felt};
use sp1_recursion_core::DIGEST_SIZE;
use sp1_stark::{
    air::MachineAir, baby_bear_poseidon2::BabyBearPoseidon2, Com, InnerChallenge, OpeningProof,
    StarkGenericConfig, StarkMachine,
};

use crate::{
    challenger::DuplexChallengerVariable,
    constraints::RecursiveVerifierConstraintFolder,
    hash::{FieldHasher, FieldHasherVariable},
    merkle_tree::{verify, MerkleProof},
    stark::MerkleProofVariable,
    witness::{WitnessWriter, Witnessable},
    BabyBearFriConfig, BabyBearFriConfigVariable, CircuitConfig, TwoAdicPcsProofVariable,
};

use super::{
    PublicValuesOutputDigest, SP1CompressShape, SP1CompressVerifier, SP1CompressWitnessValues,
    SP1CompressWitnessVariable,
};

/// A program to verify a batch of recursive proofs and aggregate their public values.
#[derive(Debug, Clone, Copy)]
pub struct SP1MerkleProofVerifier<C, SC> {
    _phantom: PhantomData<(C, SC)>,
}

/// The shape of the compress proof with vk validation proofs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SP1CompressWithVkeyShape {
    pub compress_shape: SP1CompressShape,
    pub merkle_tree_height: usize,
}

/// Witness layout for the compress stage verifier.
pub struct SP1MerkleProofWitnessVariable<
    C: CircuitConfig<F = BabyBear>,
    SC: FieldHasherVariable<C> + BabyBearFriConfigVariable<C>,
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
#[serde(bound(serialize = "SC::Digest: Serialize"))]
#[serde(bound(deserialize = "SC::Digest: Deserialize<'de>"))]
pub struct SP1MerkleProofWitnessValues<SC: FieldHasher<BabyBear>> {
    pub vk_merkle_proofs: Vec<MerkleProof<BabyBear, SC>>,
    pub values: Vec<SC::Digest>,
    pub root: SC::Digest,
}

impl<C, SC> SP1MerkleProofVerifier<C, SC>
where
    SC: BabyBearFriConfigVariable<C>,
    C: CircuitConfig<F = SC::Val, EF = SC::Challenge>,
{
    /// Verify (via Merkle tree) that the vkey digests of a proof belong to a specified set (encoded
    /// the Merkle tree proofs in input).
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
            verify(builder, proof, value, root);
            if value_assertions {
                SC::assert_digest_eq(builder, expected_value, value);
            } else {
                SC::assert_digest_eq(builder, value, value);
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SP1CompressWithVKeyVerifier<C, SC, A> {
    _phantom: PhantomData<(C, SC, A)>,
}

/// Witness layout for the verifier of the proof shape phase of the compress stage.
pub struct SP1CompressWithVKeyWitnessVariable<
    C: CircuitConfig<F = BabyBear>,
    SC: BabyBearFriConfigVariable<C>,
> {
    pub compress_var: SP1CompressWitnessVariable<C, SC>,
    pub merkle_var: SP1MerkleProofWitnessVariable<C, SC>,
}

/// An input layout for the verifier of the proof shape phase of the compress stage.
pub struct SP1CompressWithVKeyWitnessValues<SC: StarkGenericConfig + FieldHasher<BabyBear>> {
    pub compress_val: SP1CompressWitnessValues<SC>,
    pub merkle_val: SP1MerkleProofWitnessValues<SC>,
}

impl<C, SC, A> SP1CompressWithVKeyVerifier<C, SC, A>
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
    /// Verify the proof shape phase of the compress stage.
    pub fn verify(
        builder: &mut Builder<C>,
        machine: &StarkMachine<SC, A>,
        input: SP1CompressWithVKeyWitnessVariable<C, SC>,
        value_assertions: bool,
        kind: PublicValuesOutputDigest,
    ) {
        let values = input
            .compress_var
            .vks_and_proofs
            .iter()
            .map(|(vk, _)| vk.hash(builder))
            .collect::<Vec<_>>();
        let vk_root = input.merkle_var.root.map(|x| builder.eval(x));
        SP1MerkleProofVerifier::verify(builder, values, input.merkle_var, value_assertions);
        SP1CompressVerifier::verify(builder, machine, input.compress_var, vk_root, kind);
    }
}

impl<SC: BabyBearFriConfig + FieldHasher<BabyBear>> SP1CompressWithVKeyWitnessValues<SC> {
    pub fn shape(&self) -> SP1CompressWithVkeyShape {
        let merkle_tree_height = self.merkle_val.vk_merkle_proofs.first().unwrap().path.len();
        SP1CompressWithVkeyShape { compress_shape: self.compress_val.shape(), merkle_tree_height }
    }
}

impl SP1MerkleProofWitnessValues<BabyBearPoseidon2> {
    pub fn dummy(num_proofs: usize, height: usize) -> Self {
        let dummy_digest = [BabyBear::zero(); DIGEST_SIZE];
        let vk_merkle_proofs =
            vec![MerkleProof { index: 0, path: vec![dummy_digest; height] }; num_proofs];
        let values = vec![dummy_digest; num_proofs];

        Self { vk_merkle_proofs, values, root: dummy_digest }
    }
}

impl SP1CompressWithVKeyWitnessValues<BabyBearPoseidon2> {
    pub fn dummy<A: MachineAir<BabyBear>>(
        machine: &StarkMachine<BabyBearPoseidon2, A>,
        shape: &SP1CompressWithVkeyShape,
    ) -> Self {
        let compress_val =
            SP1CompressWitnessValues::<BabyBearPoseidon2>::dummy(machine, &shape.compress_shape);
        let num_proofs = compress_val.vks_and_proofs.len();
        let merkle_val = SP1MerkleProofWitnessValues::<BabyBearPoseidon2>::dummy(
            num_proofs,
            shape.merkle_tree_height,
        );
        Self { compress_val, merkle_val }
    }
}

impl<C: CircuitConfig<F = BabyBear, EF = InnerChallenge>, SC: BabyBearFriConfigVariable<C>>
    Witnessable<C> for SP1CompressWithVKeyWitnessValues<SC>
where
    Com<SC>: Witnessable<C, WitnessVariable = <SC as FieldHasherVariable<C>>::DigestVariable>,
    // This trait bound is redundant, but Rust-Analyzer is not able to infer it.
    SC: FieldHasher<BabyBear>,
    <SC as FieldHasher<BabyBear>>::Digest: Witnessable<C, WitnessVariable = SC::DigestVariable>,
    OpeningProof<SC>: Witnessable<C, WitnessVariable = TwoAdicPcsProofVariable<C, SC>>,
{
    type WitnessVariable = SP1CompressWithVKeyWitnessVariable<C, SC>;

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
