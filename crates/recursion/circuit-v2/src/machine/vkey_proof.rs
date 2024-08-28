use std::marker::PhantomData;

use itertools::Itertools;
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_commit::Mmcs;
use p3_matrix::dense::RowMajorMatrix;
use sp1_recursion_compiler::ir::{Builder, Felt};
use sp1_recursion_core_v2::DIGEST_SIZE;
use sp1_stark::{air::MachineAir, StarkGenericConfig, StarkMachine};

use crate::{
    challenger::DuplexChallengerVariable,
    constraints::RecursiveVerifierConstraintFolder,
    hash::{FieldHasher, FieldHasherVariable},
    merkle_tree::{verify, MerkleProof},
    stark::MerkleProofVariable,
    BabyBearFriConfigVariable, CircuitConfig,
};

use super::{SP1CompressVerifier, SP1CompressWitnessValues, SP1CompressWitnessVariable};

/// A program to verify a batch of recursive proofs and aggregate their public values.
#[derive(Debug, Clone, Copy)]
pub struct SP1MerkleProofVerifier<C, SC> {
    _phantom: PhantomData<(C, SC)>,
}

/// Witness layout for the compress stage verifier.
pub struct SP1MerkleProofWitnessVariable<
    C: CircuitConfig<F = BabyBear>,
    SC: FieldHasherVariable<C> + BabyBearFriConfigVariable<C>,
> {
    /// The shard proofs to verify.
    pub vk_digests_and_merkle_proofs: Vec<(SC::DigestVariable, MerkleProofVariable<C, SC>)>,
}

/// An input layout for the reduce verifier.
pub struct SP1MerkleProofWitnessValues<SC: FieldHasher<BabyBear>> {
    pub vk_digests_and_merkle_proofs: Vec<MerkleProof<BabyBear, SC>>,
}

impl<C, SC> SP1MerkleProofVerifier<C, SC>
where
    SC: BabyBearFriConfigVariable<C>,
    C: CircuitConfig<F = SC::Val, EF = SC::Challenge>,
{
    /// Verify a batch of recursive proofs and aggregate their public values.
    ///
    /// The compression verifier can aggregate proofs of different kinds:
    /// - Core proofs: proofs which are recursive proof of a batch of SP1 shard proofs. The
    ///   implementation in this function assumes a fixed recursive verifier speicified by
    ///   `recursive_vk`.
    /// - Deferred proofs: proofs which are recursive proof of a batch of deferred proofs. The
    ///   implementation in this function assumes a fixed deferred verification program specified by
    ///   `deferred_vk`.
    /// - Compress proofs: these are proofs which refer to a prove of this program. The key for it
    ///   is part of public values will be propagated accross all levels of recursion and will be
    ///   checked against itself as in [sp1_prover::Prover] or as in [super::SP1RootVerifier].
    pub fn verify(
        builder: &mut Builder<C>,
        digests: Vec<SC::DigestVariable>,
        input: SP1MerkleProofWitnessVariable<C, SC>,
        // TODO: add vk correctness check.
        // vk_root: SC::Digest,
        // Inclusion proof for the compressed vk.
        // vk_inclusion_proof: SP1MerkleProofWitnessVariable<C, SC>,
    ) {
        for ((root, proof), value) in input.vk_digests_and_merkle_proofs.into_iter().zip(digests) {
            // SC::assert_digest_eq(builder, *root, SC::hash(builder, &proof.root));
            verify(builder, proof, value, root);
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
    ) {
        let values =
            input.compress_var.vks_and_proofs.iter().map(|(vk, _)| vk.hash(builder)).collect_vec();
        SP1MerkleProofVerifier::verify(builder, values, input.merkle_var);
        SP1CompressVerifier::verify(builder, machine, input.compress_var);
    }
}
