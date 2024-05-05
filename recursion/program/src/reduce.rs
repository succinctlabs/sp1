//! ReduceProgram defines a recursive program that can reduce a set of proofs into a single proof.
//!
//! Specifically, this program takes in an ordered list of proofs where each proof can be either an
//! SP1 Core proof or a recursive VM proof of itself. Each proof is verified and then checked to
//! ensure that each transition is valid. Finally, the overall start and end values are committed to.
//!
//! Because SP1 uses a global challenger system, `verify_start_challenger` is witnessed and used to
//! verify each core proof. As each core proof is verified, its commitment and public values are
//! observed into `reconstruct_challenger`. After recursively reducing down to one proof,
//! `reconstruct_challenger` must equal `verify_start_challenger`.
//!
//! "Deferred proofs" can also be passed in and verified. These are fully reduced proofs that were
//! committed to within the core VM. These proofs can then be verified here and then reconstructed
//! into a single digest which is checked against what was committed. Note that it is possible for
//! reduce to be called with only deferred proofs, and not any core/recursive proofs. In this case,
//! the start and end pc/shard values should be equal to each other.
//!
//! Because the program can verify ranges of a full SP1 proof, the program exposes `is_complete`
//! which is only 1 if the program has fully verified the execution of the program, including all
//! deferred proofs.

#![allow(clippy::needless_range_loop)]

use std::array;
use std::borrow::{Borrow, BorrowMut};

use itertools::{izip, Itertools};
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{AbstractField, PrimeField32, TwoAdicField};
use sp1_core::air::{MachineAir, PublicValues};
use sp1_core::air::{Word, POSEIDON_NUM_WORDS, PV_DIGEST_NUM_WORDS};
use sp1_core::stark::StarkMachine;
use sp1_core::stark::{Com, RiscvAir, ShardProof, StarkGenericConfig, StarkVerifyingKey};
use sp1_core::utils::{sp1_fri_config, BabyBearPoseidon2};
use sp1_recursion_compiler::config::InnerConfig;
use sp1_recursion_compiler::ir::{Array, Builder, Config, Ext, ExtConst, Felt, Var};
use sp1_recursion_compiler::prelude::DslVariable;
use sp1_recursion_core::air::{RecursionPublicValues, RECURSIVE_PROOF_NUM_PV_ELTS};
use sp1_recursion_core::cpu::Instruction;
use sp1_recursion_core::runtime::{RecursionProgram, D, DIGEST_SIZE};

use sp1_recursion_compiler::prelude::*;

use crate::challenger::{CanObserveVariable, DuplexChallengerVariable};
use crate::fri::TwoAdicFriPcsVariable;
use crate::fri::TwoAdicMultiplicativeCosetVariable;
use crate::hints::Hintable;
use crate::stark::{RecursiveVerifierConstraintFolder, StarkVerifier};
use crate::types::ShardProofVariable;
use crate::types::{QuotientData, VerifyingKeyVariable};
use crate::utils::{
    assert_challenger_eq_pv, assign_challenger_from_pv, const_fri_config, felt2var,
    get_challenger_public_values, get_preprocessed_data, hash_vkey, var2felt,
};

/// A program for recursively verifying a batch of SP1 proofs.
#[derive(Debug, Clone, Copy)]
pub struct SP1RecursiveVerifier<C: Config, SC: StarkGenericConfig> {
    _phantom: std::marker::PhantomData<(C, SC)>,
}

#[derive(Debug, Clone, Copy)]
pub struct SP1DeferredVerifier<C: Config, SC: StarkGenericConfig, A> {
    _phantom: std::marker::PhantomData<(C, SC, A)>,
}

/// A program to verify a batch of recursive proofs and aggregate their public values.
#[derive(Debug, Clone, Copy)]
pub struct SP1ReduceVerifier<C: Config, SC: StarkGenericConfig, A> {
    _phantom: std::marker::PhantomData<(C, SC, A)>,
}

/// The program that gets a final verifier at the root of the tree.
#[derive(Debug, Clone, Copy)]
pub struct SP1RootVerifier<C: Config, SC: StarkGenericConfig, A> {
    _phantom: std::marker::PhantomData<(C, SC, A)>,
}

pub struct SP1RootMemoryLayout<'a, SC: StarkGenericConfig, A: MachineAir<SC::Val>> {
    pub machine: &'a StarkMachine<SC, A>,
    pub proof: ShardProof<SC>,
    pub is_reduce: bool,
}

/// An input layout for the reduce verifier.
pub struct SP1ReduceMemoryLayout<'a, SC: StarkGenericConfig, A: MachineAir<SC::Val>> {
    pub reduce_vk: &'a StarkVerifyingKey<SC>,
    pub recursive_machine: &'a StarkMachine<SC, A>,
    pub shard_proofs: Vec<ShardProof<SC>>,
    pub is_complete: bool,
    pub kinds: Vec<ReduceProgramType>,
}

pub struct SP1RecursionMemoryLayout<'a, SC: StarkGenericConfig, A: MachineAir<SC::Val>> {
    pub vk: &'a StarkVerifyingKey<SC>,
    pub machine: &'a StarkMachine<SC, A>,
    pub shard_proofs: Vec<ShardProof<SC>>,
    pub leaf_challenger: &'a SC::Challenger,
    pub initial_reconstruct_challenger: SC::Challenger,
    pub is_complete: bool,
}

/// The different types of programs that can be verified by the `SP1ReduceVerifier`.
#[derive(Debug, Clone, Copy)]
pub enum ReduceProgramType {
    /// A batch of proofs that are all SP1 Core proofs.
    Core = 0,
    /// A batch of proofs that are all deferred proofs.
    Deferred = 1,
    /// A batch of proofs that are reduce proofs of a higher level in the recursion tree.
    Reduce = 2,
}

#[derive(DslVariable, Clone)]
pub struct SP1RecursionMemoryLayoutVariable<C: Config> {
    pub vk: VerifyingKeyVariable<C>,

    pub shard_proofs: Array<C, ShardProofVariable<C>>,
    pub shard_chip_quotient_data: Array<C, Array<C, QuotientData<C>>>,
    pub shard_sorted_indices: Array<C, Array<C, Var<C::N>>>,

    pub preprocessed_sorted_idxs: Array<C, Var<C::N>>,
    pub prep_domains: Array<C, TwoAdicMultiplicativeCosetVariable<C>>,

    pub leaf_challenger: DuplexChallengerVariable<C>,
    pub initial_reconstruct_challenger: DuplexChallengerVariable<C>,

    pub is_complete: Var<C::N>,
}

#[derive(DslVariable, Clone)]
pub struct SP1ReduceMemoryLayoutVariable<C: Config> {
    pub reduce_vk: VerifyingKeyVariable<C>,

    pub reduce_prep_sorted_idxs: Array<C, Var<C::N>>,
    pub reduce_prep_domains: Array<C, TwoAdicMultiplicativeCosetVariable<C>>,

    pub shard_proofs: Array<C, ShardProofVariable<C>>,
    pub shard_chip_quotient_data: Array<C, Array<C, QuotientData<C>>>,
    pub shard_sorted_indices: Array<C, Array<C, Var<C::N>>>,

    pub kinds: Array<C, Var<C::N>>,
    pub is_complete: Var<C::N>,
}

#[derive(DslVariable, Clone)]
pub struct SP1RootMemoryLayoutVariable<C: Config> {
    pub proof: ShardProofVariable<C>,
    pub chip_quotient_data: Array<C, QuotientData<C>>,
    pub sorted_indices: Array<C, Var<C::N>>,
    pub is_reduce: Var<C::N>,
}

impl SP1RecursiveVerifier<InnerConfig, BabyBearPoseidon2> {
    pub fn setup() -> RecursionProgram<BabyBear> {
        let mut builder = Builder::<InnerConfig>::default();

        let input: SP1RecursionMemoryLayoutVariable<_> = builder.uninit();
        SP1RecursionMemoryLayout::<BabyBearPoseidon2, RiscvAir<_>>::witness(&input, &mut builder);

        builder.compile_program()
    }

    pub fn build_with_witness(
        machine: &StarkMachine<BabyBearPoseidon2, RiscvAir<BabyBear>>,
    ) -> RecursionProgram<BabyBear> {
        let mut builder = Builder::<InnerConfig>::default();

        let input: SP1RecursionMemoryLayoutVariable<_> = builder.uninit();

        let pcs = TwoAdicFriPcsVariable {
            config: const_fri_config(&mut builder, &sp1_fri_config()),
        };
        SP1RecursiveVerifier::verify(&mut builder, &pcs, machine, input);

        let mut recursive_program = builder.compile_program();
        recursive_program.instructions[0] = Instruction::dummy();
        recursive_program
    }

    pub fn build(
        machine: &StarkMachine<BabyBearPoseidon2, RiscvAir<BabyBear>>,
    ) -> RecursionProgram<BabyBear> {
        let mut builder = Builder::<InnerConfig>::default();

        let input: SP1RecursionMemoryLayoutVariable<_> = builder.uninit();
        SP1RecursionMemoryLayout::<BabyBearPoseidon2, RiscvAir<_>>::witness(&input, &mut builder);

        let pcs = TwoAdicFriPcsVariable {
            config: const_fri_config(&mut builder, &sp1_fri_config()),
        };
        SP1RecursiveVerifier::verify(&mut builder, &pcs, machine, input);

        builder.compile_program()
    }
}

impl<A> SP1ReduceVerifier<InnerConfig, BabyBearPoseidon2, A>
where
    A: MachineAir<BabyBear> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, InnerConfig>>,
{
    pub fn build(
        machine: &StarkMachine<BabyBearPoseidon2, A>,
        recursive_vk: &StarkVerifyingKey<BabyBearPoseidon2>,
        deferred_vk: &StarkVerifyingKey<BabyBearPoseidon2>,
    ) -> RecursionProgram<BabyBear> {
        let mut builder = Builder::<InnerConfig>::default();

        let input: SP1ReduceMemoryLayoutVariable<_> = builder.uninit();
        SP1ReduceMemoryLayout::<BabyBearPoseidon2, A>::witness(&input, &mut builder);

        let pcs = TwoAdicFriPcsVariable {
            config: const_fri_config(&mut builder, machine.config().pcs().fri_config()),
        };
        SP1ReduceVerifier::verify(
            &mut builder,
            &pcs,
            machine,
            input,
            recursive_vk,
            deferred_vk,
        );

        builder.compile_program()
    }
}

impl<A> SP1RootVerifier<InnerConfig, BabyBearPoseidon2, A>
where
    A: MachineAir<BabyBear> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, InnerConfig>>,
{
    pub fn build(
        machine: &StarkMachine<BabyBearPoseidon2, A>,
        vk: &StarkVerifyingKey<BabyBearPoseidon2>,
    ) -> RecursionProgram<BabyBear> {
        let mut builder = Builder::<InnerConfig>::default();
        let input: SP1RootMemoryLayoutVariable<_> = builder.uninit();
        SP1RootMemoryLayout::<BabyBearPoseidon2, A>::witness(&input, &mut builder);

        let pcs = TwoAdicFriPcsVariable {
            config: const_fri_config(&mut builder, machine.config().pcs().fri_config()),
        };

        SP1RootVerifier::verify(&mut builder, &pcs, machine, vk, &input);

        builder.compile_program()
    }
}

/// Assertions on the public values describing a complete recursive proof state.
fn assert_complete<C: Config>(
    builder: &mut Builder<C>,
    public_values: &RecursionPublicValues<Felt<C::F>>,
    end_reconstruct_challenger: &DuplexChallengerVariable<C>,
) {
    let RecursionPublicValues {
        deferred_proofs_digest,
        next_pc,
        start_shard,
        cumulative_sum,
        start_reconstruct_deferred_digest,
        end_reconstruct_deferred_digest,
        leaf_challenger,
        ..
    } = public_values;
    // Assert that `end_pc` is equal to zero (so program execution has completed)
    builder.assert_felt_eq(*next_pc, C::F::zero());

    // Assert that the start shard is equal to 1.
    builder.assert_felt_eq(*start_shard, C::F::one());

    // The challenger has been fully verified.

    // The start_reconstruct_challenger should be the same as an empty challenger observing the
    // verifier key and the start pc. This was already verified when verifying the leaf proofs so
    // there is no need to assert it here.

    // Assert that the end reconstruct challenger is equal to the leaf challenger.
    assert_challenger_eq_pv(builder, end_reconstruct_challenger, *leaf_challenger);

    // The deferred digest has been fully reconstructed.

    // The start reconstruct digest should be zero.
    for start_digest_word in start_reconstruct_deferred_digest {
        builder.assert_felt_eq(*start_digest_word, C::F::zero());
    }
    // The end reconstruct digest should be equal to the deferred proofs digest.
    for (end_digest_word, deferred_digest_word) in end_reconstruct_deferred_digest
        .iter()
        .zip_eq(deferred_proofs_digest.iter())
    {
        builder.assert_felt_eq(*end_digest_word, *deferred_digest_word);
    }

    // Assert that the cumulative sum is zero.
    for b in cumulative_sum.iter() {
        builder.assert_felt_eq(*b, C::F::zero());
    }
}

fn proof_data_from_vk<C: Config, SC, A>(
    builder: &mut Builder<C>,
    vk: &StarkVerifyingKey<SC>,
    machine: &StarkMachine<SC, A>,
) -> (
    VerifyingKeyVariable<C>,
    Array<C, TwoAdicMultiplicativeCosetVariable<C>>,
    Array<C, Var<C::N>>,
)
where
    SC: StarkGenericConfig<
        Val = C::F,
        Challenge = C::EF,
        Domain = TwoAdicMultiplicativeCoset<C::F>,
    >,
    A: MachineAir<SC::Val>,
    Com<SC>: Into<[SC::Val; DIGEST_SIZE]>,
{
    let mut commitment = builder.dyn_array(DIGEST_SIZE);
    for (i, value) in vk.commit.clone().into().iter().enumerate() {
        builder.set(&mut commitment, i, *value);
    }
    let pc_start: Felt<_> = builder.eval(vk.pc_start);

    let vk_variable = VerifyingKeyVariable {
        commitment,
        pc_start,
    };

    let (prep_sorted_indices_val, prep_domains_val) = get_preprocessed_data(machine, vk);

    let mut prep_sorted_indices = builder.dyn_array::<Var<_>>(prep_sorted_indices_val.len());
    let mut prep_domains =
        builder.dyn_array::<TwoAdicMultiplicativeCosetVariable<_>>(prep_domains_val.len());

    for (i, value) in prep_sorted_indices_val.iter().enumerate() {
        builder.set(
            &mut prep_sorted_indices,
            i,
            C::N::from_canonical_usize(*value),
        );
    }

    for (i, value) in prep_domains_val.iter().enumerate() {
        let domain: TwoAdicMultiplicativeCosetVariable<_> = builder.constant(*value);
        builder.set(&mut prep_domains, i, domain);
    }

    (vk_variable, prep_domains, prep_sorted_indices)
}

impl<C: Config, SC, A> SP1RootVerifier<C, SC, A>
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
    /// Verify a proof with given vk and aggregate their public values.
    ///
    /// is_reduce : if the proof is a reduce proof, we will assert that the given vk indentifies
    /// with the reduce vk digest of public inputs.
    fn verify(
        builder: &mut Builder<C>,
        pcs: &TwoAdicFriPcsVariable<C>,
        machine: &StarkMachine<SC, A>,
        vk: &StarkVerifyingKey<SC>,
        input: &SP1RootMemoryLayoutVariable<C>,
    ) {
        // Get the verifying key info from the vk.
        let (vk, prep_domains, prep_sorted_indices) = proof_data_from_vk(builder, vk, machine);

        let SP1RootMemoryLayoutVariable {
            proof,
            chip_quotient_data,
            sorted_indices,
            is_reduce,
        } = input;

        // Get the public inputs from the proof.
        let public_values_elements = (0..RECURSIVE_PROOF_NUM_PV_ELTS)
            .map(|i| builder.get(&proof.public_values, i))
            .collect::<Vec<Felt<_>>>();
        let public_values: &RecursionPublicValues<Felt<C::F>> =
            public_values_elements.as_slice().borrow();

        // Assert that the proof is complete.
        //
        // *Remark*: here we are assuming on that the program we are verifying indludes the check
        // of completeness conditions are satisfied if the flag is set to one, so we are only
        // checking the `is_complete` flag in this program.
        builder.assert_felt_eq(public_values.is_complete, C::F::one());

        // If the proof is a reduce proof, assert that the vk is the same as the reduce vk from the
        // public values.
        builder.if_eq(*is_reduce, C::N::one()).then(|builder| {
            let vk_digest = hash_vkey(builder, &vk, &prep_domains, &prep_sorted_indices);
            for (i, reduce_digest_elem) in public_values.reduce_vk_digest.iter().enumerate() {
                let vk_digest_elem = builder.get(&vk_digest, i);
                builder.assert_felt_eq(vk_digest_elem, *reduce_digest_elem);
            }
        });
        // Verify the proof.

        let mut challenger = DuplexChallengerVariable::new(builder);
        // Observe the vk and start pc.
        challenger.observe(builder, vk.commitment.clone());
        challenger.observe(builder, vk.pc_start);
        // Observe the main commitment and public values.
        challenger.observe(builder, proof.commitment.main_commit.clone());
        for j in 0..machine.num_pv_elts() {
            let element = builder.get(&proof.public_values, j);
            challenger.observe(builder, element);
        }
        // verify proof.
        StarkVerifier::<C, SC>::verify_shard(
            builder,
            &vk,
            pcs,
            machine,
            &mut challenger,
            proof,
            chip_quotient_data,
            sorted_indices,
            &prep_sorted_indices,
            &prep_domains,
        );

        // Commit to the public values, broadcasting the same ones.
        let mut public_values_array = builder.dyn_array::<Felt<_>>(RECURSIVE_PROOF_NUM_PV_ELTS);
        for (i, value) in public_values_elements.iter().enumerate() {
            builder.set(&mut public_values_array, i, *value);
        }

        builder.commit_public_values(&public_values_array);
    }
}

impl<C: Config, SC, A> SP1ReduceVerifier<C, SC, A>
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
    /// Verify a batch of recursive proofs and aggregate their public values.
    fn verify(
        builder: &mut Builder<C>,
        pcs: &TwoAdicFriPcsVariable<C>,
        machine: &StarkMachine<SC, A>,
        input: SP1ReduceMemoryLayoutVariable<C>,
        recursive_vk: &StarkVerifyingKey<SC>,
        deferred_vk: &StarkVerifyingKey<SC>,
    ) {
        let SP1ReduceMemoryLayoutVariable {
            reduce_vk,
            reduce_prep_sorted_idxs,
            reduce_prep_domains,
            shard_proofs,
            shard_chip_quotient_data,
            shard_sorted_indices,
            kinds,
            is_complete,
        } = input;

        // Initialize the values for the aggregated public output.

        let mut reduce_public_values_stream: Vec<Felt<_>> = (0..RECURSIVE_PROOF_NUM_PV_ELTS)
            .map(|_| builder.uninit())
            .collect();

        let reduce_public_values: &mut RecursionPublicValues<_> =
            reduce_public_values_stream.as_mut_slice().borrow_mut();

        // Compute the digest of reduce_vk and input the value to the public values.
        let reduce_vk_digest = hash_vkey(
            builder,
            &reduce_vk,
            &reduce_prep_domains,
            &reduce_prep_sorted_idxs,
        );

        reduce_public_values.reduce_vk_digest =
            array::from_fn(|i| builder.get(&reduce_vk_digest, i));

        // Assert that there is at least one proof.
        builder.assert_usize_ne(shard_proofs.len(), 0);
        // Assert that the number of proofs is equal to the number of kinds.
        builder.assert_usize_eq(shard_proofs.len(), kinds.len());

        // Initialize the consistency check variables.
        let sp1_vk_digest: [Felt<_>; DIGEST_SIZE] = array::from_fn(|_| builder.uninit());
        let pc: Felt<_> = builder.uninit();
        let shard: Felt<_> = builder.uninit();
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

        // Collect verifying keys for each kind of program.
        let (recursive_vk_variable, rec_rep_domains, rec_prep_sorted_indices) =
            proof_data_from_vk(builder, recursive_vk, machine);
        let (deferred_vk_variable, def_rep_domains, def_prep_sorted_indices) =
            proof_data_from_vk(builder, deferred_vk, machine);

        // Verify the shard proofs and connect the values.
        builder.range(0, shard_proofs.len()).for_each(|i, builder| {
            // Load the proof.
            let proof = builder.get(&shard_proofs, i);
            // Load the public values from the proof.
            let current_public_values_elements = (0..RECURSIVE_PROOF_NUM_PV_ELTS)
                .map(|i| builder.get(&proof.public_values, i))
                .collect::<Vec<Felt<_>>>();

            let current_public_values: &RecursionPublicValues<Felt<C::F>> =
                current_public_values_elements.as_slice().borrow();

            // If the proof is the first proof, initialize the values.
            builder.if_eq(i, C::N::zero()).then(|builder| {
                // Initialize globa and accumulated values.

                // Initialize the sp1_vk digest
                for (digest, first_digest) in sp1_vk_digest
                    .iter()
                    .zip(current_public_values.sp1_vk_digest)
                {
                    builder.assign(*digest, first_digest);
                }

                // Initiallize start pc.
                builder.assign(
                    reduce_public_values.start_pc,
                    current_public_values.start_pc,
                );
                builder.assign(pc, current_public_values.start_pc);

                // Initialize start shard.
                builder.assign(shard, current_public_values.start_shard);
                builder.assign(
                    reduce_public_values.start_shard,
                    current_public_values.start_shard,
                );

                // Initialize the leaf challenger.
                assign_challenger_from_pv(
                    builder,
                    &mut leaf_challenger,
                    current_public_values.leaf_challenger,
                );
                // Initialize the reconstruct challenger.
                assign_challenger_from_pv(
                    builder,
                    &mut initial_reconstruct_challenger,
                    current_public_values.start_reconstruct_challenger,
                );
                assign_challenger_from_pv(
                    builder,
                    &mut reconstruct_challenger,
                    current_public_values.start_reconstruct_challenger,
                );

                // Assign the commited values and deferred proof digests.
                for (word, current_word) in committed_value_digest
                    .iter()
                    .zip_eq(current_public_values.committed_value_digest.iter())
                {
                    for (byte, current_byte) in word.0.iter().zip_eq(current_word.0.iter()) {
                        builder.assign(*byte, *current_byte);
                    }
                }

                for (digest, current_digest) in deferred_proofs_digest
                    .iter()
                    .zip_eq(current_public_values.deferred_proofs_digest.iter())
                {
                    builder.assign(*digest, *current_digest);
                }

                // Initialize the start and end of deferred digests.
                for (digest, current_digest, global_digest) in izip!(
                    reconstruct_deferred_digest.iter(),
                    current_public_values
                        .start_reconstruct_deferred_digest
                        .iter(),
                    reduce_public_values
                        .start_reconstruct_deferred_digest
                        .iter()
                ) {
                    builder.assign(*digest, *current_digest);
                    builder.assign(*global_digest, *current_digest);
                }
            });

            // Assert that the current values match the accumulated values.
            // Assert that the sp1_vk digest is always the same.
            for (digest, current) in sp1_vk_digest
                .iter()
                .zip(current_public_values.sp1_vk_digest)
            {
                builder.assert_felt_eq(*digest, current);
            }
            // Assert that the start pc is equal to the current pc.
            builder.assert_felt_eq(pc, current_public_values.start_pc);
            // Verfiy that the shard is equal to the current shard.
            builder.assert_felt_eq(shard, current_public_values.start_shard);
            // Assert that the leaf challenger is always the same.
            assert_challenger_eq_pv(
                builder,
                &leaf_challenger,
                current_public_values.leaf_challenger,
            );
            // Assert that the current challenger matches the start reconstruct challenger.
            assert_challenger_eq_pv(
                builder,
                &reconstruct_challenger,
                current_public_values.start_reconstruct_challenger,
            );
            // Assert that the commited digests are the same.
            for (word, current_word) in committed_value_digest
                .iter()
                .zip_eq(current_public_values.committed_value_digest.iter())
            {
                for (byte, current_byte) in word.0.iter().zip_eq(current_word.0.iter()) {
                    builder.assert_felt_eq(*byte, *current_byte);
                }
            }
            // Assert that the deferred proof digests are the same.
            for (digest, current_digest) in deferred_proofs_digest
                .iter()
                .zip_eq(current_public_values.deferred_proofs_digest.iter())
            {
                builder.assert_felt_eq(*digest, *current_digest);
            }
            // Assert that the start deferred digest is equal to the current deferred digest.
            for (digest, current_digest) in reconstruct_deferred_digest.iter().zip_eq(
                current_public_values
                    .start_reconstruct_deferred_digest
                    .iter(),
            ) {
                builder.assert_felt_eq(*digest, *current_digest);
            }
            // Verify the shard proof.

            // Get the proof kind.
            let kind = builder.get(&kinds, i);
            // Initialize values for verifying key and proof data.
            let vk: VerifyingKeyVariable<_> = builder.uninit();
            let prep_domains: Array<_, TwoAdicMultiplicativeCosetVariable<_>> = builder.uninit();
            let prep_sorted_idxs: Array<_, Var<_>> = builder.uninit();
            // Set the correct value given the value of kind.
            builder
                .if_eq(
                    kind,
                    C::N::from_canonical_u32(ReduceProgramType::Core as u32),
                )
                .then(|builder| {
                    builder.assign(vk.clone(), recursive_vk_variable.clone());
                    builder.assign(prep_domains.clone(), rec_rep_domains.clone());
                    builder.assign(prep_sorted_idxs.clone(), rec_prep_sorted_indices.clone());
                });
            builder
                .if_eq(
                    kind,
                    C::N::from_canonical_u32(ReduceProgramType::Deferred as u32),
                )
                .then(|builder| {
                    builder.assign(vk.clone(), deferred_vk_variable.clone());
                    builder.assign(prep_domains.clone(), def_rep_domains.clone());
                    builder.assign(prep_sorted_idxs.clone(), def_prep_sorted_indices.clone());
                });
            builder
                .if_eq(
                    kind,
                    C::N::from_canonical_u32(ReduceProgramType::Reduce as u32),
                )
                .then(|builder| {
                    builder.assign(vk.clone(), reduce_vk.clone());
                    builder.assign(prep_domains.clone(), reduce_prep_domains.clone());
                    builder.assign(prep_sorted_idxs.clone(), reduce_prep_sorted_idxs.clone());
                });
            // Todo: assert that Kind must be one of these values.

            // Verify the shard proof given the correct data.
            let chip_quotient_data = builder.get(&shard_chip_quotient_data, i);
            let chip_sorted_idxs = builder.get(&shard_sorted_indices, i);

            // Prepare a challenger.
            let mut challenger = DuplexChallengerVariable::new(builder);
            // Observe the vk and start pc.
            challenger.observe(builder, vk.commitment.clone());
            challenger.observe(builder, vk.pc_start);
            // Observe the main commitment and public values.
            challenger.observe(builder, proof.commitment.main_commit.clone());
            for j in 0..machine.num_pv_elts() {
                let element = builder.get(&proof.public_values, j);
                challenger.observe(builder, element);
            }
            // verify proof.
            StarkVerifier::<C, SC>::verify_shard(
                builder,
                &vk,
                pcs,
                machine,
                &mut challenger,
                &proof,
                &chip_quotient_data,
                &chip_sorted_idxs,
                &prep_sorted_idxs,
                &prep_domains,
            );
            // Update the accumulated values.

            // Update pc to be the next pc.
            builder.assign(pc, current_public_values.next_pc);
            // Update the shard to be the next shard.
            builder.assign(shard, current_public_values.next_shard);
            // Update the reconstruct challenger.
            assign_challenger_from_pv(
                builder,
                &mut reconstruct_challenger,
                current_public_values.end_reconstruct_challenger,
            );
            // Update the deferred digest.
            for (digest, current_digest) in reconstruct_deferred_digest
                .iter()
                .zip_eq(current_public_values.end_reconstruct_deferred_digest.iter())
            {
                builder.assign(*digest, *current_digest);
            }

            // Update the cumulative sum.
            for (sum_element, current_sum_element) in cumulative_sum
                .iter()
                .zip_eq(current_public_values.cumulative_sum.iter())
            {
                builder.assign(*sum_element, *sum_element + *current_sum_element);
            }
        });

        // Update the global values from the last accumulated values.
        // Set sp1_vk digest to the one from the proof values.
        reduce_public_values.sp1_vk_digest = sp1_vk_digest;
        // Set next_pc to be the last pc (which is the same as accumulated pc)
        reduce_public_values.next_pc = pc;
        // Set next shard to be the last shard (which is the same as accumulated shard)
        reduce_public_values.next_shard = shard;
        // Set the leaf challenger to it's value.
        let values = get_challenger_public_values(builder, &leaf_challenger);
        reduce_public_values.leaf_challenger = values;
        // Set the start reconstruct challenger to be the initial reconstruct challenger.
        let values = get_challenger_public_values(builder, &initial_reconstruct_challenger);
        reduce_public_values.start_reconstruct_challenger = values;
        // Set the end reconstruct challenger to be the last reconstruct challenger.
        let values = get_challenger_public_values(builder, &reconstruct_challenger);
        reduce_public_values.end_reconstruct_challenger = values;

        // Assign the deffered proof digests.
        reduce_public_values.deferred_proofs_digest = deferred_proofs_digest;
        // Assign the committed value digests.
        reduce_public_values.committed_value_digest = committed_value_digest;
        // Assign the cumulative sum.
        reduce_public_values.cumulative_sum = cumulative_sum;

        // If the proof is complete, make completeness assertions and set the flag. Otherwise, check
        // the flag is zero and set the public value to zero.
        builder.if_eq(is_complete, C::N::one()).then_or_else(
            |builder| {
                builder.assign(reduce_public_values.is_complete, C::F::one());
                assert_complete(builder, reduce_public_values, &reconstruct_challenger)
            },
            |builder| {
                builder.assert_var_eq(is_complete, C::N::zero());
                builder.assign(reduce_public_values.is_complete, C::F::zero());
            },
        );

        // Commit the public values.
        let mut reduce_public_values_array =
            builder.dyn_array::<Felt<_>>(RECURSIVE_PROOF_NUM_PV_ELTS);
        for (i, value) in reduce_public_values_stream.iter().enumerate() {
            builder.set(&mut reduce_public_values_array, i, *value);
        }

        builder.commit_public_values(&reduce_public_values_array)
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
    /// Verify a batch of SP1 proofs and aggregate their public values.
    fn verify(
        builder: &mut Builder<C>,
        pcs: &TwoAdicFriPcsVariable<C>,
        machine: &StarkMachine<SC, RiscvAir<SC::Val>>,
        input: SP1RecursionMemoryLayoutVariable<C>,
    ) {
        let SP1RecursionMemoryLayoutVariable {
            vk,
            shard_proofs,
            shard_chip_quotient_data,
            shard_sorted_indices,
            preprocessed_sorted_idxs,
            prep_domains,
            leaf_challenger,
            initial_reconstruct_challenger,
            is_complete,
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
        // Verify proofs, validate transitions, and update accumulation variables.
        builder.range(0, shard_proofs.len()).for_each(|i, builder| {
            let proof = builder.get(&shard_proofs, i);

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

                // Shard
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

            // If the shard is zero, verify the global initial conditions hold on challenger and pc.
            let shard = felt2var(builder, public_values.shard);
            builder.if_eq(shard, C::N::one()).then(|builder| {
                // This should be the first proof as well
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
            // Assert that the next_pc is different from the start_pc.
            builder.assert_felt_ne(public_values.start_pc, public_values.next_pc);
            // Assert that the start_pc is not zero (this means program has halted in a non-last
            // shard).
            builder.assert_felt_ne(public_values.start_pc, C::F::zero());

            // Assert that the shard of the proof is equal to the current shard.
            builder.assert_felt_eq(current_shard, public_values.shard);

            // Assert that exit code is the same for all proofs.
            builder.assert_felt_eq(exit_code, public_values.exit_code);

            // Assert that the committed value digests are all the same.

            // Assert that the deferred proof digest is the same for all proofs.
            for (digest, current_digest) in deferred_proofs_digest
                .iter()
                .zip_eq(public_values.deferred_proofs_digest.iter())
            {
                builder.assert_felt_eq(*digest, *current_digest);
            }

            // Verify the shard proof.
            let chip_quotient_data = builder.get(&shard_chip_quotient_data, i);
            let chip_sorted_idxs = builder.get(&shard_sorted_indices, i);

            let mut challenger = leaf_challenger.copy(builder);
            StarkVerifier::<C, SC>::verify_shard(
                builder,
                &vk,
                pcs,
                machine,
                &mut challenger,
                &proof,
                &chip_quotient_data,
                &chip_sorted_idxs,
                &preprocessed_sorted_idxs,
                &prep_domains,
            );

            // Update the reconstruct challenger, cumulative sum, shard number, and program counter.
            reconstruct_challenger.observe(builder, proof.commitment.main_commit);
            for j in 0..machine.num_pv_elts() {
                let element = builder.get(&proof.public_values, j);
                reconstruct_challenger.observe(builder, element);
            }

            // Increment the shard count by one.
            builder.assign(current_shard, current_shard + C::F::one());

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

        // Compute vk digest.
        let vk_digest = hash_vkey(builder, &vk, &prep_domains, &preprocessed_sorted_idxs);
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
        recursion_public_values.exit_code = zero;
        recursion_public_values.is_complete = is_complete_felt;

        // If the proof represents a complete proof, make completeness assertions.
        //
        // *Remark*: In this program, this only happends if there is one shard and the program has
        // no deferred proofs to verify. However, the completeness check is independent of these
        // facts.
        builder.if_eq(is_complete, C::N::one()).then(|builder| {
            assert_complete(builder, recursion_public_values, &reconstruct_challenger)
        });

        // Commit to the public values.
        let mut recursion_public_values_array =
            builder.dyn_array::<Felt<_>>(RECURSIVE_PROOF_NUM_PV_ELTS);
        for (i, value) in recursion_public_values_stream.iter().enumerate() {
            builder.set(&mut recursion_public_values_array, i, *value);
        }

        builder.commit_public_values(&recursion_public_values_array)
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
    fn verify() {}
}

// #[derive(Debug, Clone, Copy)]
// pub struct ReduceProgram;

// impl ReduceProgram {
//     /// The program that can reduce a set of proofs into a single proof.
//     pub fn build() -> RecursionProgram<Val> {
//         let mut reduce_program = Self::define(false);
//         reduce_program.instructions[0] = Instruction::dummy();
//         reduce_program
//     }

//     /// The program used for setting up the state of memory for the prover.
//     pub fn setup() -> RecursionProgram<Val> {
//         Self::define(true)
//     }

//     /// A definition for the program.
//     pub fn define(setup: bool) -> RecursionProgram<Val> {
//         // Initialize the sp1 and recursion maachines.
//         let core_machine = RiscvAir::machine(BabyBearPoseidon2::default());
//         let reduce_machine = RecursionAirWideDeg3::machine(BabyBearPoseidon2::default());
//         let compress_machine = RecursionAirSkinnyDeg7::machine(BabyBearPoseidon2::compressed());

//         // Initialize the builder.
//         let mut builder = AsmBuilder::<F, EF>::default();

//         // Initialize the sp1 and recursion configs as constants..
//         let sp1_config = const_fri_config(&mut builder, sp1_fri_config());
//         let reduce_config = const_fri_config(&mut builder, default_fri_config());
//         let compress_config = const_fri_config(&mut builder, compressed_fri_config());
//         let sp1_pcs = TwoAdicFriPcsVariable { config: sp1_config };
//         let reduce_pcs = TwoAdicFriPcsVariable {
//             config: reduce_config,
//         };
//         let compress_pcs = TwoAdicFriPcsVariable {
//             config: compress_config,
//         };

//         // Allocate empty space on the stack for the inputs.
//         //
//         // In the case where setup is not true, the values on the stack will all be witnessed
//         // with the appropriate values using the hinting API.
//         let is_recursive_flags: Array<_, Var<_>> = builder.uninit();
//         let chip_quotient_data: Array<_, Array<_, QuotientData<_>>> = builder.uninit();
//         let sorted_indices: Array<_, Array<_, Var<_>>> = builder.uninit();
//         let verify_start_challenger: DuplexChallengerVariable<_> = builder.uninit();
//         let reconstruct_challenger: DuplexChallengerVariable<_> = builder.uninit();
//         let prep_sorted_indices: Array<_, Var<_>> = builder.uninit();
//         let prep_domains: Array<_, TwoAdicMultiplicativeCosetVariable<_>> = builder.uninit();
//         let reduce_prep_sorted_indices: Array<_, Var<_>> = builder.uninit();
//         let reduce_prep_domains: Array<_, TwoAdicMultiplicativeCosetVariable<_>> = builder.uninit();
//         let compress_prep_sorted_indices: Array<_, Var<_>> = builder.uninit();
//         let compress_prep_domains: Array<_, TwoAdicMultiplicativeCosetVariable<_>> =
//             builder.uninit();
//         let sp1_vk: VerifyingKeyVariable<_> = builder.uninit();
//         let reduce_vk: VerifyingKeyVariable<_> = builder.uninit();
//         let compress_vk: VerifyingKeyVariable<_> = builder.uninit();
//         let initial_committed_values_digest: Sha256DigestVariable<_> = builder.uninit();
//         let initial_deferred_proofs_digest: DigestVariable<_> = builder.uninit();
//         let initial_start_pc: Felt<_> = builder.uninit();
//         let initial_exit_code: Felt<_> = builder.uninit();
//         let initial_start_shard: Felt<_> = builder.uninit();
//         let mut reconstruct_deferred_digest: DigestVariable<_> = builder.uninit();
//         let proofs: Array<_, ShardProofVariable<_>> = builder.uninit();
//         let deferred_chip_quotient_data: Array<_, Array<_, QuotientData<_>>> = builder.uninit();
//         let deferred_sorted_indices: Array<_, Array<_, Var<_>>> = builder.uninit();
//         let num_deferred_proofs: Var<_> = builder.uninit();
//         let deferred_proofs: Array<_, ShardProofVariable<_>> = builder.uninit();
//         let is_complete: Var<_> = builder.uninit();
//         let is_compressed: Var<_> = builder.uninit();

//         // Setup the memory for the prover.
//         //
//         // If the program is being setup, we need to witness the inputs using the hinting API
//         // and setup the correct state of memory.
//         if setup {
//             Vec::<usize>::witness(&is_recursive_flags, &mut builder);
//             Vec::<Vec<QuotientDataValues>>::witness(&chip_quotient_data, &mut builder);
//             Vec::<Vec<usize>>::witness(&sorted_indices, &mut builder);
//             DuplexChallenger::witness(&verify_start_challenger, &mut builder);
//             DuplexChallenger::witness(&reconstruct_challenger, &mut builder);
//             Vec::<usize>::witness(&prep_sorted_indices, &mut builder);
//             Vec::<TwoAdicMultiplicativeCoset<BabyBear>>::witness(&prep_domains, &mut builder);
//             Vec::<usize>::witness(&reduce_prep_sorted_indices, &mut builder);
//             Vec::<TwoAdicMultiplicativeCoset<BabyBear>>::witness(
//                 &reduce_prep_domains,
//                 &mut builder,
//             );
//             Vec::<usize>::witness(&compress_prep_sorted_indices, &mut builder);
//             Vec::<TwoAdicMultiplicativeCoset<BabyBear>>::witness(
//                 &compress_prep_domains,
//                 &mut builder,
//             );
//             StarkVerifyingKey::<SC>::witness(&sp1_vk, &mut builder);
//             StarkVerifyingKey::<SC>::witness(&reduce_vk, &mut builder);
//             StarkVerifyingKey::<SC>::witness(&compress_vk, &mut builder);
//             <[Word<BabyBear>; PV_DIGEST_NUM_WORDS] as Hintable<C>>::witness(
//                 &initial_committed_values_digest,
//                 &mut builder,
//             );
//             InnerDigest::witness(&initial_deferred_proofs_digest, &mut builder);
//             BabyBear::witness(&initial_start_pc, &mut builder);
//             BabyBear::witness(&initial_exit_code, &mut builder);
//             BabyBear::witness(&initial_start_shard, &mut builder);
//             InnerDigest::witness(&reconstruct_deferred_digest, &mut builder);

//             let num_proofs = is_recursive_flags.len();
//             let mut proofs_target = builder.dyn_array(num_proofs);
//             builder.range(0, num_proofs).for_each(|i, builder| {
//                 let proof = ShardProof::<SC>::read(builder);
//                 builder.set(&mut proofs_target, i, proof);
//             });
//             builder.assign(proofs.clone(), proofs_target);

//             Vec::<Vec<QuotientDataValues>>::witness(&deferred_chip_quotient_data, &mut builder);
//             Vec::<Vec<usize>>::witness(&deferred_sorted_indices, &mut builder);
//             Vec::<ShardProof<SC>>::witness(&deferred_proofs, &mut builder);
//             let num_deferred_proofs_var = deferred_proofs.len();
//             builder.assign(num_deferred_proofs, num_deferred_proofs_var);
//             usize::witness(&is_complete, &mut builder);
//             usize::witness(&is_compressed, &mut builder);

//             return builder.compile_program();
//         }

//         let num_proofs = is_recursive_flags.len();
//         let zero: Var<_> = builder.constant(F::zero());
//         let zero_felt: Felt<_> = builder.constant(F::zero());
//         let one: Var<_> = builder.constant(F::one());
//         let one_felt: Felt<_> = builder.constant(F::one());

//         // Setup the recursive challenger.
//         builder.cycle_tracker("stage-b-setup-recursion-challenger");
//         let mut recursion_challenger = DuplexChallengerVariable::new(&mut builder);
//         for j in 0..DIGEST_SIZE {
//             let element = builder.get(&reduce_vk.commitment, j);
//             recursion_challenger.observe(&mut builder, element);
//         }
//         recursion_challenger.observe(&mut builder, reduce_vk.pc_start);
//         builder.cycle_tracker("stage-b-setup-recursion-challenger");

//         // Hash vkey + pc_start + prep_domains into a single digest.
//         let sp1_vk_digest = hash_vkey(&mut builder, &sp1_vk, &prep_domains, &prep_sorted_indices);
//         let recursion_vk_digest = hash_vkey(
//             &mut builder,
//             &reduce_vk,
//             &reduce_prep_domains,
//             &reduce_prep_sorted_indices,
//         );

//         // Global variables that will be commmitted to at the end.
//         let global_committed_values_digest: Sha256DigestVariable<_> =
//             initial_committed_values_digest;
//         let global_deferred_proofs_digest: DigestVariable<_> = initial_deferred_proofs_digest;
//         let global_start_pc: Felt<_> = initial_start_pc;
//         let global_next_pc: Felt<_> = builder.uninit();
//         let global_exit_code: Felt<_> = initial_exit_code;
//         let global_start_shard: Felt<_> = initial_start_shard;
//         let global_next_shard: Felt<_> = builder.uninit();
//         let global_cumulative_sum: Ext<_, _> = builder.eval(EF::zero().cons());
//         let start_reconstruct_challenger = reconstruct_challenger.copy(&mut builder);
//         let start_reconstruct_deferred_digest =
//             clone_array(&mut builder, &reconstruct_deferred_digest);

//         // Previous proof's values.
//         let prev_next_pc: Felt<_> = builder.uninit();
//         let prev_next_shard: Felt<_> = builder.uninit();

//         // For each proof:
//         // 1) If it's the first proof of this batch, ensure that the start values are correct.
//         // 2) If it's not the first proof, ensure that the global values are the same and the
//         //    transitions are valid.
//         // 3) If it's the last proof of this batch, set the global end variables.
//         // 4) If it's not the last proof, update the previous values.
//         let constrain_shard_transitions =
//             |proof_index: Var<_>,
//              builder: &mut Builder<C>,
//              committed_value_digest_words: &[Word<Felt<_>>; PV_DIGEST_NUM_WORDS],
//              start_pc: Felt<_>,
//              next_pc: Felt<_>,
//              start_shard: Felt<_>,
//              next_shard: Felt<_>,
//              exit_code: Felt<_>| {
//                 let committed_value_digest =
//                     Sha256DigestVariable::from_words(builder, committed_value_digest_words);
//                 builder.if_eq(proof_index, zero).then_or_else(
//                     // First proof: ensure that witnessed start values are correct.
//                     |builder| {
//                         for i in 0..(PV_DIGEST_NUM_WORDS * WORD_SIZE) {
//                             let element = builder.get(&global_committed_values_digest.bytes, i);
//                             let proof_element = builder.get(&committed_value_digest.bytes, i);
//                             builder.assert_felt_eq(element, proof_element);
//                         }
//                         builder.assert_felt_eq(global_start_pc, start_pc);
//                         builder.assert_felt_eq(global_start_shard, start_shard);
//                         builder.assert_felt_eq(global_exit_code, exit_code);
//                     },
//                     // Non-first proofs: verify global values are same and transitions are valid.
//                     |builder| {
//                         // Assert that committed_values_digest and exit_code are the same
//                         for j in 0..(PV_DIGEST_NUM_WORDS * WORD_SIZE) {
//                             let global_element =
//                                 builder.get(&global_committed_values_digest.bytes, j);
//                             let element = builder.get(&committed_value_digest.bytes, j);
//                             builder.assert_felt_eq(global_element, element);
//                         }
//                         builder.assert_felt_eq(global_exit_code, exit_code);

//                         // Shard should be previous next_shard.
//                         builder.assert_felt_eq(start_shard, prev_next_shard);
//                         // Start pc should be equal to next_pc declared in previous proof.
//                         builder.assert_felt_eq(start_pc, prev_next_pc);
//                     },
//                 );
//                 builder.if_eq(proof_index, num_proofs - one).then_or_else(
//                     // If it's the last proof, set global end variables.
//                     |builder| {
//                         builder.assign(global_next_shard, next_shard);
//                         builder.assign(global_next_pc, next_pc);
//                     },
//                     // If it's not the last proof, update previous values.
//                     |builder| {
//                         builder.assign(prev_next_pc, next_pc);
//                         builder.assign(prev_next_shard, next_shard);
//                     },
//                 );
//             };

//         // Verify sp1 and recursive proofs.
//         builder.range(0, num_proofs).for_each(|i, builder| {
//             let proof = builder.get(&proofs, i);
//             let sorted_indices = builder.get(&sorted_indices, i);
//             let chip_quotient_data = builder.get(&chip_quotient_data, i);
//             let is_recursive = builder.get(&is_recursive_flags, i);

//             builder.if_eq(is_recursive, zero).then_or_else(
//                 // Handle the case where the proof is a sp1 proof.
//                 |builder| {
//                     // Clone the variable pointer to reconstruct_challenger.
//                     let reconstruct_challenger = reconstruct_challenger.clone();
//                     // Extract public values.
//                     let mut pv_elements = Vec::new();
//                     for i in 0..PROOF_MAX_NUM_PVS {
//                         let element = builder.get(&proof.public_values, i);
//                         pv_elements.push(element);
//                     }
//                     let pv = PublicValues::<Word<Felt<_>>, Felt<_>>::from_vec(pv_elements);

//                     // Verify shard transitions.
//                     let next_shard: Felt<_> = builder.uninit();
//                     let next_pc_var = felt2var(builder, pv.next_pc);
//                     builder.if_eq(next_pc_var, zero).then_or_else(
//                         // If next_pc is 0, then next_shard should be 0.
//                         |builder| {
//                             builder.assign(next_shard, zero_felt);
//                         },
//                         // Otherwise, next_shard should be shard + 1.
//                         |builder| {
//                             let shard_plus_one: Felt<_> = builder.eval(pv.shard + one_felt);
//                             builder.assign(next_shard, shard_plus_one);
//                         },
//                     );
//                     constrain_shard_transitions(
//                         i,
//                         builder,
//                         &pv.committed_value_digest,
//                         pv.start_pc,
//                         pv.next_pc,
//                         pv.shard,
//                         next_shard,
//                         pv.exit_code,
//                     );

//                     // Need to convert the shard as a felt to a variable, since `if_eq` only handles
//                     // variables.
//                     let shard_f = pv.shard;
//                     let shard = felt2var(builder, shard_f);

//                     // Handle the case where the shard is the first shard.
//                     builder.if_eq(shard, one).then(|builder| {
//                         // This should be the first proof as well
//                         builder.assert_var_eq(i, zero);

//                         // Start pc should be sp1_vk.pc_start
//                         builder.assert_felt_eq(pv.start_pc, sp1_vk.pc_start);

//                         // Clone the variable pointer to verify_start_challenger.
//                         let mut reconstruct_challenger = reconstruct_challenger.clone();
//                         // Initialize the reconstruct challenger from empty challenger.
//                         reconstruct_challenger.reset(builder);
//                         reconstruct_challenger.observe(builder, sp1_vk.commitment.clone());
//                         reconstruct_challenger.observe(builder, sp1_vk.pc_start);

//                         // Make sure the start reconstruct challenger is correct, since we will
//                         // commit to it in public values.
//                         start_reconstruct_challenger.assert_eq(builder, &reconstruct_challenger);

//                         // Make sure start reconstruct deferred digest is fully zero.
//                         for j in 0..POSEIDON_NUM_WORDS {
//                             let element = builder.get(&start_reconstruct_deferred_digest, j);
//                             builder.assert_felt_eq(element, zero_felt);
//                         }
//                     });

//                     // Observe current proof commit and public values into reconstruct challenger.
//                     for j in 0..DIGEST_SIZE {
//                         let element = builder.get(&proof.commitment.main_commit, j);
//                         reconstruct_challenger.clone().observe(builder, element);
//                     }
//                     for j in 0..SP1_PROOF_NUM_PV_ELTS {
//                         let element = builder.get(&proof.public_values, j);
//                         reconstruct_challenger.clone().observe(builder, element);
//                     }

//                     // Accumulate lookup bus.
//                     let num_chips = proof.opened_values.chips.len();
//                     builder.range(0, num_chips).for_each(|j, builder| {
//                         let chip = builder.get(&proof.opened_values.chips, j);
//                         let new_sum: Ext<_, _> =
//                             builder.eval(global_cumulative_sum + chip.cumulative_sum);
//                         builder.assign(global_cumulative_sum, new_sum);
//                     });

//                     // Verify proof with copy of witnessed challenger.
//                     let mut current_challenger = verify_start_challenger.copy(builder);

//                     // Verify the shard.
//                     StarkVerifier::<C, BabyBearPoseidon2>::verify_shard(
//                         builder,
//                         &sp1_vk.clone(),
//                         &sp1_pcs,
//                         &core_machine,
//                         &mut current_challenger,
//                         &proof,
//                         chip_quotient_data.clone(),
//                         sorted_indices.clone(),
//                         prep_sorted_indices.clone(),
//                         prep_domains.clone(),
//                     );
//                 },
//                 // Handle the case where the proof is a recursive proof.
//                 |builder| {
//                     let mut reconstruct_challenger = reconstruct_challenger.clone();
//                     let mut pv_elements = Vec::new();
//                     for i in 0..PROOF_MAX_NUM_PVS {
//                         let element = builder.get(&proof.public_values, i);
//                         pv_elements.push(element);
//                     }
//                     let pv: &RecursionPublicValues<Felt<_>> = pv_elements.as_slice().borrow();

//                     // Verify shard transitions.
//                     constrain_shard_transitions(
//                         i,
//                         builder,
//                         &pv.committed_value_digest,
//                         pv.start_pc,
//                         pv.next_pc,
//                         pv.start_shard,
//                         pv.next_shard,
//                         pv.exit_code,
//                     );

//                     // Assert that the current reconstruct_challenger is the same as the proof's
//                     // start_reconstruct_challenger, then fast-forward to end_reconstruct_challenger.
//                     assert_challenger_eq_pv(
//                         builder,
//                         &reconstruct_challenger,
//                         pv.start_reconstruct_challenger,
//                     );
//                     assign_challenger_from_pv(
//                         builder,
//                         &mut reconstruct_challenger,
//                         pv.end_reconstruct_challenger,
//                     );

//                     // Assert that the current deferred_proof_digest is the same as the proof's
//                     // start_reconstruct_deferred_digest, then fast-forward to end digest.
//                     for j in 0..DIGEST_SIZE {
//                         let element = builder.get(&reconstruct_deferred_digest, j);
//                         builder.assert_felt_eq(element, pv.start_reconstruct_deferred_digest[j]);
//                     }
//                     for j in 0..DIGEST_SIZE {
//                         builder.set(
//                             &mut reconstruct_deferred_digest,
//                             j,
//                             pv.end_reconstruct_deferred_digest[j],
//                         );
//                     }

//                     // Assert that sp1_vk, recursion_vk, and verify_start_challenger are the same.
//                     for j in 0..DIGEST_SIZE {
//                         let element = builder.get(&sp1_vk_digest, j);
//                         builder.assert_felt_eq(element, pv.sp1_vk_digest[j]);
//                     }
//                     for j in 0..DIGEST_SIZE {
//                         let element = builder.get(&recursion_vk_digest, j);
//                         builder.assert_felt_eq(element, pv.recursion_vk_digest[j]);
//                     }
//                     assert_challenger_eq_pv(
//                         builder,
//                         &verify_start_challenger,
//                         pv.verify_start_challenger,
//                     );

//                     // Accumulate lookup bus.
//                     let pv_cumulative_sum = builder.ext_from_base_slice(&pv.cumulative_sum);
//                     let new_sum: Ext<_, _> =
//                         builder.eval(global_cumulative_sum + pv_cumulative_sum);
//                     builder.assign(global_cumulative_sum, new_sum);

//                     // Setup the recursive challenger to use for verifying.
//                     let mut current_challenger = recursion_challenger.copy(builder);
//                     for j in 0..DIGEST_SIZE {
//                         let element = builder.get(&proof.commitment.main_commit, j);
//                         current_challenger.observe(builder, element);
//                     }
//                     builder.range(0, PROOF_MAX_NUM_PVS).for_each(|j, builder| {
//                         let element = builder.get(&proof.public_values, j);
//                         current_challenger.observe(builder, element);
//                     });

//                     builder.if_eq(is_compressed, BabyBear::one()).then_or_else(
//                         |builder| {
//                             StarkVerifier::<C, BabyBearPoseidon2>::verify_shard(
//                                 builder,
//                                 &compress_vk,
//                                 &compress_pcs,
//                                 &compress_machine,
//                                 &mut current_challenger.clone(),
//                                 &proof,
//                                 chip_quotient_data.clone(),
//                                 sorted_indices.clone(),
//                                 reduce_prep_sorted_indices.clone(),
//                                 reduce_prep_domains.clone(),
//                             );
//                         },
//                         |builder| {
//                             StarkVerifier::<C, BabyBearPoseidon2>::verify_shard(
//                                 builder,
//                                 &reduce_vk,
//                                 &reduce_pcs,
//                                 &reduce_machine,
//                                 &mut current_challenger.clone(),
//                                 &proof,
//                                 chip_quotient_data.clone(),
//                                 sorted_indices.clone(),
//                                 reduce_prep_sorted_indices.clone(),
//                                 reduce_prep_domains.clone(),
//                             );
//                         },
//                     )
//                 },
//             );
//         });

//         // If num_proofs is 0, set end values to same as start values.
//         builder.if_eq(num_proofs, zero).then(|builder| {
//             builder.assign(global_next_shard, global_start_shard);
//             builder.assign(global_next_pc, global_start_pc);
//         });

//         // Verify deferred proofs and acculumate to deferred proofs digest.
//         builder
//             .range(0, num_deferred_proofs)
//             .for_each(|i, builder| {
//                 let proof = builder.get(&deferred_proofs, i);
//                 let sorted_indices = builder.get(&deferred_sorted_indices, i);
//                 let chip_quotient_data = builder.get(&deferred_chip_quotient_data, i);
//                 let mut challenger = recursion_challenger.copy(builder);
//                 for j in 0..DIGEST_SIZE {
//                     let element = builder.get(&proof.commitment.main_commit, j);
//                     challenger.observe(builder, element);
//                 }
//                 builder.range(0, PROOF_MAX_NUM_PVS).for_each(|j, builder| {
//                     let element = builder.get(&proof.public_values, j);
//                     challenger.observe(builder, element);
//                 });

//                 // Validate proof public values.
//                 // 1) Ensure that the proof is complete.
//                 let mut pv_elements = Vec::new();
//                 for i in 0..PROOF_MAX_NUM_PVS {
//                     let element = builder.get(&proof.public_values, i);
//                     pv_elements.push(element);
//                 }
//                 let pv: &RecursionPublicValues<Felt<_>> = pv_elements.as_slice().borrow();
//                 builder.assert_felt_eq(pv.is_complete, one_felt);
//                 // 2) Ensure recursion vkey is correct
//                 for j in 0..DIGEST_SIZE {
//                     let element = builder.get(&recursion_vk_digest, j);
//                     builder.assert_felt_eq(element, pv.recursion_vk_digest[j]);
//                 }

//                 // Verify the shard.
//                 StarkVerifier::<C, BabyBearPoseidon2>::verify_shard(
//                     builder,
//                     &reduce_vk.clone(),
//                     &reduce_pcs,
//                     &reduce_machine,
//                     &mut challenger,
//                     &proof,
//                     chip_quotient_data.clone(),
//                     sorted_indices.clone(),
//                     reduce_prep_sorted_indices.clone(),
//                     reduce_prep_domains.clone(),
//                 );

//                 // Update deferred proof digest
//                 // poseidon2( current_digest[..8] || pv.sp1_vk_digest[..8] || pv.committed_value_digest[..32] )
//                 let mut poseidon_inputs = builder.array(48);
//                 builder.range(0, 8).for_each(|j, builder| {
//                     let element = builder.get(&reconstruct_deferred_digest, j);
//                     builder.set(&mut poseidon_inputs, j, element);
//                 });
//                 for j in 0..DIGEST_SIZE {
//                     let input_index: Var<_> = builder.constant(F::from_canonical_usize(j + 8));
//                     builder.set(&mut poseidon_inputs, input_index, pv.sp1_vk_digest[j]);
//                 }
//                 for j in 0..PV_DIGEST_NUM_WORDS {
//                     for k in 0..WORD_SIZE {
//                         let input_index: Var<_> =
//                             builder.eval(F::from_canonical_usize(j * WORD_SIZE + k + 16));
//                         let element = pv.committed_value_digest[j][k];
//                         builder.set(&mut poseidon_inputs, input_index, element);
//                     }
//                 }
//                 let new_digest = builder.poseidon2_hash(&poseidon_inputs);
//                 for j in 0..DIGEST_SIZE {
//                     let element = builder.get(&new_digest, j);
//                     builder.set(&mut reconstruct_deferred_digest, j, element);
//                 }
//             });

//         // If witnessed as complete, then verify all of the final state is correct.
//         builder.if_eq(is_complete, one).then_or_else(
//             |builder| {
//                 // 1) Proof begins at shard == 1.
//                 let global_start_shard_var = felt2var(builder, global_start_shard);
//                 builder.assert_var_eq(global_start_shard_var, one);

//                 // 2) Proof begins at pc == sp1_vk.pc_start.
//                 builder.assert_felt_eq(global_start_pc, sp1_vk.pc_start);

//                 // 3) Execution has halted (next_pc == 0 && next_shard == 0).
//                 let global_next_pc_var = felt2var(builder, global_next_pc);
//                 builder.assert_var_eq(global_next_pc_var, zero);
//                 let global_next_shard_var = felt2var(builder, global_next_shard);
//                 builder.assert_var_eq(global_next_shard_var, zero);

//                 // 4) reconstruct_challenger has been fully reconstructed.
//                 //    a) start_reconstruct_challenger == challenger after observing vk and pc_start.
//                 let mut expected_challenger = DuplexChallengerVariable::new(builder);
//                 expected_challenger.observe(builder, sp1_vk.commitment.clone());
//                 expected_challenger.observe(builder, sp1_vk.pc_start);
//                 start_reconstruct_challenger.assert_eq(builder, &expected_challenger);
//                 //    b) end_reconstruct_challenger == verify_start_challenger.
//                 reconstruct_challenger.assert_eq(builder, &verify_start_challenger);

//                 // 5) reconstruct_deferred_digest has been fully reconstructed.
//                 //    a) start_reconstruct_deferred_digest == 0.
//                 for j in 0..DIGEST_SIZE {
//                     let element = builder.get(&start_reconstruct_deferred_digest, j);
//                     builder.assert_felt_eq(element, zero_felt);
//                 }
//                 //    b) end_reconstruct_deferred_digest == deferred_proofs_digest.
//                 for j in 0..DIGEST_SIZE {
//                     let element = builder.get(&reconstruct_deferred_digest, j);
//                     let global_element = builder.get(&global_deferred_proofs_digest, j);
//                     builder.assert_felt_eq(element, global_element);
//                 }

//                 // 6) Verify that the cumulative sum is zero.
//                 let zero_ext: Ext<_, _> = builder.eval(EF::zero().cons());
//                 builder.assert_ext_eq(global_cumulative_sum, zero_ext);
//             },
//             // Ensure is_complete is boolean.
//             |builder| {
//                 builder.assert_var_eq(is_complete, zero);
//             },
//         );

//         // Public values:
//         // (
//         //     committed_values_digest,
//         //     deferred_proofs_digest,
//         //     start_pc,
//         //     next_pc,
//         //     exit_code,
//         //     start_shard,
//         //     end_shard,
//         //     start_reconstruct_challenger,
//         //     end_reconstruct_challenger,
//         //     start_reconstruct_deferred_digest,
//         //     end_reconstruct_deferred_digest,
//         //     sp1_vk_digest,
//         //     recursion_vk_digest,
//         //     verify_start_challenger,
//         //     cumulative_sum,
//         //     is_complete,
//         // )
//         for j in 0..(PV_DIGEST_NUM_WORDS * WORD_SIZE) {
//             let element = builder.get(&global_committed_values_digest.bytes, j);
//             builder.commit_public_value(element);
//         }
//         for j in 0..POSEIDON_NUM_WORDS {
//             let element = builder.get(&global_deferred_proofs_digest, j);
//             builder.commit_public_value(element);
//         }
//         builder.commit_public_value(global_start_pc);
//         builder.commit_public_value(global_next_pc);
//         builder.commit_public_value(global_exit_code);
//         builder.commit_public_value(global_start_shard);
//         builder.commit_public_value(global_next_shard);
//         commit_challenger(&mut builder, &start_reconstruct_challenger);
//         commit_challenger(&mut builder, &reconstruct_challenger);
//         builder.range(0, POSEIDON_NUM_WORDS).for_each(|j, builder| {
//             let element = builder.get(&start_reconstruct_deferred_digest, j);
//             builder.commit_public_value(element);
//         });
//         builder.range(0, POSEIDON_NUM_WORDS).for_each(|j, builder| {
//             let element = builder.get(&reconstruct_deferred_digest, j);
//             builder.commit_public_value(element);
//         });
//         builder.range(0, DIGEST_SIZE).for_each(|j, builder| {
//             let element = builder.get(&sp1_vk_digest, j);
//             builder.commit_public_value(element);
//         });
//         builder.range(0, DIGEST_SIZE).for_each(|j, builder| {
//             let element = builder.get(&recursion_vk_digest, j);
//             builder.commit_public_value(element);
//         });
//         commit_challenger(&mut builder, &verify_start_challenger);
//         let cumulative_sum_felts = builder.ext2felt(global_cumulative_sum);
//         builder.commit_public_values(&cumulative_sum_felts);
//         let is_complete_felt = var2felt(&mut builder, is_complete);
//         builder.commit_public_value(is_complete_felt);

//         builder.compile_program()
//     }
// }

#[cfg(test)]
mod tests {

    use p3_challenger::CanObserve;
    use p3_maybe_rayon::prelude::*;
    use sp1_core::{
        io::SP1Stdin,
        runtime::Program,
        stark::{Challenge, LocalProver, ProgramVerificationError},
    };
    use sp1_recursion_core::{
        runtime::Runtime,
        stark::{config::BabyBearPoseidon2Outer, RecursionAir, RecursionAirWideDeg3},
    };

    use super::*;

    enum Test {
        Recursion,
        Reduce,
        Compress,
        Wrap,
    }

    fn test_sp1_recursive_machine_verify(program: Program, batch_size: usize, test: Test) {
        type SC = BabyBearPoseidon2;
        type F = BabyBear;
        type EF = Challenge<SC>;

        sp1_core::utils::setup_logger();

        let machine = RiscvAir::machine(SC::default());
        let (_, vk) = machine.setup(&program);
        let mut challenger = machine.config().challenger();
        let time = std::time::Instant::now();
        let (proof, _) = sp1_core::utils::run_and_prove(program, &SP1Stdin::new(), SC::default());
        machine.verify(&vk, &proof, &mut challenger).unwrap();
        tracing::info!("Proof generated successfully");
        let elapsed = time.elapsed();
        tracing::info!("Execution proof time: {:?}", elapsed);

        // Get the and leaf challenger.
        let mut leaf_challenger = machine.config().challenger();
        vk.observe_into(&mut leaf_challenger);
        proof.shard_proofs.iter().for_each(|proof| {
            leaf_challenger.observe(proof.commitment.main_commit);
            leaf_challenger.observe_slice(&proof.public_values[0..machine.num_pv_elts()]);
        });
        // Make sure leaf challenger is not mutable anymore.
        let leaf_challenger = leaf_challenger;

        let mut layouts = Vec::new();

        let mut reconstruct_challenger = machine.config().challenger();
        vk.observe_into(&mut reconstruct_challenger);

        let is_complete = proof.shard_proofs.len() == 1;
        for batch in proof.shard_proofs.chunks(batch_size) {
            let proofs = batch.to_vec();

            layouts.push(SP1RecursionMemoryLayout {
                vk: &vk,
                machine: &machine,
                shard_proofs: proofs,
                leaf_challenger: &leaf_challenger,
                initial_reconstruct_challenger: reconstruct_challenger.clone(),
                is_complete,
            });

            for proof in batch.iter() {
                reconstruct_challenger.observe(proof.commitment.main_commit);
                reconstruct_challenger
                    .observe_slice(&proof.public_values[0..machine.num_pv_elts()]);
            }
        }

        assert_eq!(
            reconstruct_challenger.sponge_state,
            leaf_challenger.sponge_state
        );
        assert_eq!(
            reconstruct_challenger.input_buffer,
            leaf_challenger.input_buffer
        );
        assert_eq!(
            reconstruct_challenger.output_buffer,
            leaf_challenger.output_buffer
        );

        // Construct the recursion program.
        let recursive_program = SP1RecursiveVerifier::<InnerConfig, SC>::build(&machine);

        // Run the recursion programs.
        let mut records = Vec::new();

        for layout in layouts {
            let mut runtime =
                Runtime::<F, EF, _>::new(&recursive_program, machine.config().perm.clone());

            let mut witness_stream = Vec::new();
            witness_stream.extend(layout.write());

            runtime.witness_stream = witness_stream.into();
            runtime.run();
            runtime.print_stats();

            records.push(runtime.record);
        }

        // Prove all recursion programs and verify the recursive proofs.

        let recursive_config = SC::default();
        type A = RecursionAirWideDeg3<BabyBear>;
        let recursive_machine = A::machine(recursive_config.clone());
        let (rec_pk, rec_vk) = recursive_machine.setup(&recursive_program);

        // Make the recursive proofs.
        let time = std::time::Instant::now();
        let recursive_proofs = records
            .into_par_iter()
            .map(|record| {
                let mut recursive_challenger = recursive_machine.config().challenger();
                recursive_machine.prove::<LocalProver<_, _>>(
                    &rec_pk,
                    record,
                    &mut recursive_challenger,
                )
            })
            .collect::<Vec<_>>();
        let elapsed = time.elapsed();
        tracing::info!("Recursive first layer proving time: {:?}", elapsed);

        // Verify the recursive proofs.
        for rec_proof in recursive_proofs.iter() {
            let mut recursive_challenger = recursive_machine.config().challenger();
            let result = recursive_machine.verify(&rec_vk, rec_proof, &mut recursive_challenger);

            match result {
                Ok(_) => tracing::info!("Proof verified successfully"),
                Err(ProgramVerificationError::NonZeroCumulativeSum) => {
                    tracing::info!("Proof verification failed: NonZeroCumulativeSum")
                }
                e => panic!("Proof verification failed: {:?}", e),
            }
        }
        if let Test::Recursion = test {
            return;
        }

        tracing::info!("Recursive proofs verified successfully");

        // Build the reduce program.
        let reduce_program =
            SP1ReduceVerifier::<InnerConfig, _, _>::build(&recursive_machine, &rec_vk, &rec_vk);

        let (reduce_pk, reduce_vk) = recursive_machine.setup(&reduce_program);
        // Chain all the individual shard proofs.
        let mut recursive_proofs = recursive_proofs
            .into_iter()
            .flat_map(|proof| proof.shard_proofs)
            .collect::<Vec<_>>();

        // Iterate over the recursive proof batches until there is one proof remaining.
        let mut is_first_layer = true;
        let mut is_complete;
        let time = std::time::Instant::now();
        loop {
            tracing::info!("Recursive proofs: {}", recursive_proofs.len());
            is_complete = recursive_proofs.len() <= batch_size;
            recursive_proofs = recursive_proofs
                .par_chunks(batch_size)
                .map(|batch| {
                    let kind = if is_first_layer {
                        ReduceProgramType::Core
                    } else {
                        ReduceProgramType::Reduce
                    };
                    let kinds = batch.iter().map(|_| kind).collect::<Vec<_>>();
                    let input = SP1ReduceMemoryLayout {
                        reduce_vk: &reduce_vk,
                        recursive_machine: &recursive_machine,
                        shard_proofs: batch.to_vec(),
                        kinds,
                        is_complete,
                    };

                    let mut runtime = Runtime::<F, EF, _>::new(
                        &reduce_program,
                        recursive_machine.config().perm.clone(),
                    );

                    let mut witness_stream = Vec::new();
                    witness_stream.extend(input.write());

                    runtime.witness_stream = witness_stream.into();
                    runtime.run();
                    runtime.print_stats();

                    let mut recursive_challenger = recursive_machine.config().challenger();
                    let mut proof = recursive_machine.prove::<LocalProver<_, _>>(
                        &reduce_pk,
                        runtime.record,
                        &mut recursive_challenger,
                    );
                    let mut recursive_challenger = recursive_machine.config().challenger();
                    let result =
                        recursive_machine.verify(&reduce_vk, &proof, &mut recursive_challenger);

                    match result {
                        Ok(_) => tracing::info!("Proof verified successfully"),
                        Err(ProgramVerificationError::NonZeroCumulativeSum) => {
                            tracing::info!("Proof verification failed: NonZeroCumulativeSum")
                        }
                        e => panic!("Proof verification failed: {:?}", e),
                    }

                    assert_eq!(proof.shard_proofs.len(), 1);
                    proof.shard_proofs.pop().unwrap()
                })
                .collect();
            is_first_layer = false;

            if recursive_proofs.len() == 1 {
                break;
            }
        }
        let elapsed = time.elapsed();
        tracing::info!("Reduction successful, time: {:?}", elapsed);
        if let Test::Reduce = test {
            return;
        }

        assert_eq!(recursive_proofs.len(), 1);
        let reduce_proof = recursive_proofs.pop().unwrap();

        // Make the compress program.
        let compress_machine = RecursionAir::<_, 9>::machine(SC::compressed());
        let compress_program =
            SP1RootVerifier::<InnerConfig, _, _>::build(&recursive_machine, &reduce_vk);

        // Make the compress proof.
        let (compress_pk, compress_vk) = compress_machine.setup(&compress_program);

        let input = SP1RootMemoryLayout {
            machine: &recursive_machine,
            proof: reduce_proof,
            is_reduce: true,
        };

        // Run the compress program.
        let mut runtime =
            Runtime::<F, EF, _>::new(&compress_program, compress_machine.config().perm.clone());

        let mut witness_stream = Vec::new();
        witness_stream.extend(input.write());

        runtime.witness_stream = witness_stream.into();
        runtime.run();
        runtime.print_stats();
        tracing::info!("Compress program executed successfully");

        // Prove the compress program.
        let mut compress_challenger = compress_machine.config().challenger();

        let time = std::time::Instant::now();
        let mut compress_proof = compress_machine.prove::<LocalProver<_, _>>(
            &compress_pk,
            runtime.record,
            &mut compress_challenger,
        );
        let elapsed = time.elapsed();
        tracing::info!("Compress proving time: {:?}", elapsed);
        let mut compress_challenger = compress_machine.config().challenger();
        let result =
            compress_machine.verify(&compress_vk, &compress_proof, &mut compress_challenger);
        match result {
            Ok(_) => tracing::info!("Proof verified successfully"),
            Err(ProgramVerificationError::NonZeroCumulativeSum) => {
                tracing::info!("Proof verification failed: NonZeroCumulativeSum")
            }
            e => panic!("Proof verification failed: {:?}", e),
        }

        if let Test::Compress = test {
            return;
        }

        // Make the wrap program and prove.
        let wrap_machine = RecursionAir::<_, 5>::machine(BabyBearPoseidon2Outer::default());
        let wrap_program =
            SP1RootVerifier::<InnerConfig, _, _>::build(&compress_machine, &compress_vk);

        let (wrap_pk, wrap_vk) = wrap_machine.setup(&wrap_program);

        let compress_proof = compress_proof.shard_proofs.pop().unwrap();
        let input = SP1RootMemoryLayout {
            machine: &compress_machine,
            proof: compress_proof,
            is_reduce: false,
        };

        // Run the compress program.
        let mut runtime =
            Runtime::<F, EF, _>::new(&wrap_program, compress_machine.config().perm.clone());

        let mut witness_stream = Vec::new();
        witness_stream.extend(input.write());

        runtime.witness_stream = witness_stream.into();
        runtime.run();
        runtime.print_stats();
        tracing::info!("Wrap program executed successfully");

        // Prove the wrap program.
        let mut wrap_challenger = wrap_machine.config().challenger();
        let time = std::time::Instant::now();
        let wrap_proof =
            wrap_machine.prove::<LocalProver<_, _>>(&wrap_pk, runtime.record, &mut wrap_challenger);
        let elapsed = time.elapsed();
        tracing::info!("Wrap proving time: {:?}", elapsed);
        let mut wrap_challenger = wrap_machine.config().challenger();
        let result = wrap_machine.verify(&wrap_vk, &wrap_proof, &mut wrap_challenger);
        match result {
            Ok(_) => tracing::info!("Proof verified successfully"),
            Err(ProgramVerificationError::NonZeroCumulativeSum) => {
                tracing::info!("Proof verification failed: NonZeroCumulativeSum")
            }
            e => panic!("Proof verification failed: {:?}", e),
        }
        tracing::info!("Wrapping successful");
    }

    #[test]
    fn test_sp1_recursive_machine_verify_fibonacci() {
        let elf =
            include_bytes!("../../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
        test_sp1_recursive_machine_verify(Program::from(elf), 1, Test::Recursion)
    }

    #[test]
    fn test_sp1_reduce_machine_verify_fibonacci() {
        let elf =
            include_bytes!("../../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
        test_sp1_recursive_machine_verify(Program::from(elf), 1, Test::Reduce)
    }

    #[test]
    #[ignore]
    fn test_sp1_compress_machine_verify_fibonacci() {
        let elf =
            include_bytes!("../../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
        test_sp1_recursive_machine_verify(Program::from(elf), 1, Test::Compress)
    }

    #[test]
    #[ignore]
    fn test_sp1_wrap_machine_verify_fibonacci() {
        let elf =
            include_bytes!("../../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
        test_sp1_recursive_machine_verify(Program::from(elf), 1, Test::Wrap)
    }

    #[test]
    #[ignore]
    fn test_sp1_reduce_machine_verify_tendermint() {
        let elf = include_bytes!(
            "../../../examples/tendermint-benchmark/program/elf/riscv32im-succinct-zkvm-elf"
        );
        test_sp1_recursive_machine_verify(Program::from(elf), 2, Test::Reduce)
    }

    #[test]
    #[ignore]
    fn test_sp1_recursive_machine_verify_tendermint() {
        let elf = include_bytes!(
            "../../../examples/tendermint-benchmark/program/elf/riscv32im-succinct-zkvm-elf"
        );
        test_sp1_recursive_machine_verify(Program::from(elf), 2, Test::Recursion)
    }

    #[test]
    #[ignore]
    fn test_sp1_compress_machine_verify_tendermint() {
        let elf = include_bytes!(
            "../../../examples/tendermint-benchmark/program/elf/riscv32im-succinct-zkvm-elf"
        );
        test_sp1_recursive_machine_verify(Program::from(elf), 2, Test::Compress)
    }

    #[test]
    #[ignore]
    fn test_sp1_wrap_machine_verify_tendermint() {
        let elf = include_bytes!(
            "../../../examples/tendermint-benchmark/program/elf/riscv32im-succinct-zkvm-elf"
        );
        test_sp1_recursive_machine_verify(Program::from(elf), 2, Test::Wrap)
    }
}
