use std::{array, borrow::BorrowMut, marker::PhantomData};

use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;

use p3_commit::Mmcs;
use p3_matrix::dense::RowMajorMatrix;
use sp1_core::{
    air::{MachineAir, Word, POSEIDON_NUM_WORDS, PV_DIGEST_NUM_WORDS},
    stark::{ShardProof, StarkGenericConfig, StarkMachine, StarkVerifyingKey},
    utils::DIGEST_SIZE,
};
use sp1_recursion_compiler::ir::{Builder, Felt};
use sp1_recursion_core_v2::{
    air::{RecursionPublicValues, RECURSIVE_PROOF_NUM_PV_ELTS},
    D,
};
// TODO: Migrate this type to here.
use sp1_recursion_program::{fri::TwoAdicFriPcsVariable, machine::ReduceProgramType};

use crate::{challenger::CanObserveVariable, stark::StarkVerifier};
use crate::{
    challenger::DuplexChallengerVariable, constraints::RecursiveVerifierConstraintFolder,
    stark::ShardProofVariable, BabyBearFriConfigVariable, CircuitConfig, VerifyingKeyVariable,
};

/// A program to verify a batch of recursive proofs and aggregate their public values.
#[derive(Debug, Clone, Copy)]
pub struct SP1CompressVerifier<C, SC, A> {
    _phantom: PhantomData<(C, SC, A)>,
}

/// Witness layout for the compress stage verifier.
pub struct SP1CompressWitnessVariable<
    C: CircuitConfig<F = BabyBear>,
    SC: BabyBearFriConfigVariable<C>,
> {
    /// The shard proofs to verify.
    pub vks_and_proofs: Vec<(VerifyingKeyVariable<C, SC>, ShardProofVariable<C, SC>)>,
    pub is_complete: bool,
    pub kinds: Vec<ReduceProgramType>,
}

/// An input layout for the reduce verifier.
pub struct SP1CompressWitnessValues<SC: StarkGenericConfig> {
    pub vks_and_proofs: Vec<(StarkVerifyingKey<SC>, ShardProof<SC>)>,
    pub is_complete: bool,
    pub kinds: Vec<ReduceProgramType>,
}

impl<C, SC, A> SP1CompressVerifier<C, SC, A>
where
    SC: BabyBearFriConfigVariable<C>,
    C: CircuitConfig<F = SC::Val, EF = SC::Challenge, Bit = Felt<BabyBear>>,
    <SC::ValMmcs as Mmcs<BabyBear>>::ProverData<RowMajorMatrix<BabyBear>>: Clone,
    A: MachineAir<SC::Val> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
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
        input: SP1CompressWitnessVariable<C, SC>,
        // TODO: add vk correctness check.
        // vk_root: SC::Digest,
        // Inclusion proof for the compressed vk.
        // vk_inclusion_proof: proof,
    ) {
        // Read input.
        let SP1CompressWitnessVariable {
            vks_and_proofs,
            is_complete,
            kinds,
        } = input;

        // Initialize the values for the aggregated public output.

        let mut reduce_public_values_stream: Vec<Felt<_>> = (0..RECURSIVE_PROOF_NUM_PV_ELTS)
            .map(|_| builder.uninit())
            .collect();
        let reduce_public_values: &mut RecursionPublicValues<_> =
            reduce_public_values_stream.as_mut_slice().borrow_mut();

        // TODO: add vk correctness check.

        // Make sure there is at least one proof.
        assert!(!vks_and_proofs.is_empty());

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

        // Verify proofs, check consistency, and aggregate public values.
        for (i, (vk, shard_proof)) in vks_and_proofs.into_iter().enumerate() {
            // Verify the shard proof.

            // Prepare a challenger.
            let mut challenger = machine.config().challenger_variable(builder);

            // Observe the vk and start pc.
            challenger.observe(builder, vk.commitment);
            challenger.observe(builder, vk.pc_start);

            // Observe the main commitment and public values.
            challenger.observe(builder, shard_proof.commitment.main_commit);
            challenger.observe_slice(
                builder,
                shard_proof.public_values[0..machine.num_pv_elts()]
                    .iter()
                    .copied(),
            );
            StarkVerifier::verify_shard(builder, &vk, machine, &mut challenger, &shard_proof);
        }
    }
}
