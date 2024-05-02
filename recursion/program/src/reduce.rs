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
use std::marker::PhantomData;
use std::ptr::hash;

use itertools::Itertools;
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{AbstractField, PrimeField32, TwoAdicField};
use sp1_core::air::{MachineAir, PublicValues, SP1_PROOF_NUM_PV_ELTS, WORD_SIZE};
use sp1_core::air::{Word, POSEIDON_NUM_WORDS, PV_DIGEST_NUM_WORDS};
use sp1_core::runtime::Program;
use sp1_core::stark::{Com, RiscvAir, ShardProof, StarkGenericConfig, StarkVerifyingKey};
use sp1_core::stark::{StarkMachine, PROOF_MAX_NUM_PVS};
use sp1_core::utils::baby_bear_poseidon2::{compressed_fri_config, default_fri_config};
use sp1_core::utils::sp1_fri_config;
use sp1_core::utils::{BabyBearPoseidon2, InnerDigest};
use sp1_recursion_compiler::asm::{AsmBuilder, AsmConfig};
use sp1_recursion_compiler::config::InnerConfig;
use sp1_recursion_compiler::ir::{Array, Builder, Config, Ext, ExtConst, Felt, Var};
use sp1_recursion_compiler::prelude::DslVariable;
use sp1_recursion_core::air::{RecursionPublicValues, RECURSIVE_PROOF_NUM_PV_ELTS};
use sp1_recursion_core::cpu::Instruction;
use sp1_recursion_core::runtime::{RecursionProgram, DIGEST_SIZE};
use sp1_recursion_core::stark::{RecursionAirSkinnyDeg7, RecursionAirWideDeg3};

use sp1_recursion_compiler::prelude::*;

use crate::challenger::{CanObserveVariable, DuplexChallengerVariable};
use crate::fri::types::DigestVariable;
use crate::fri::TwoAdicFriPcsVariable;
use crate::fri::TwoAdicMultiplicativeCosetVariable;
use crate::hints::Hintable;
use crate::stark::{RecursiveVerifierConstraintFolder, StarkVerifier};
use crate::types::{QuotientData, QuotientDataValues, VerifyingKeyVariable};
use crate::types::{Sha256DigestVariable, ShardProofVariable};
use crate::utils::{
    assert_challenger_eq_pv, assign_challenger_from_pv, clone_array, commit_challenger,
    const_fri_config, felt2var, get_challenger_public_values, hash_vkey, var2felt,
};

/// A program for recursively verifying a batch of SP1 proofs.
#[derive(Debug, Clone, Copy)]
pub struct SP1RecursiveVerifier<C: Config, SC: StarkGenericConfig> {
    _phantom: std::marker::PhantomData<(C, SC)>,
}

#[derive(Debug, Clone, Copy)]
pub struct SP1DeferredVerifier<C: Config, SC: StarkGenericConfig> {
    _phantom: std::marker::PhantomData<(C, SC)>,
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

pub struct SP1RecursionMemoryLayout<'a, SC: StarkGenericConfig, A: MachineAir<SC::Val>> {
    pub vk: &'a StarkVerifyingKey<SC>,
    pub machine: &'a StarkMachine<SC, A>,
    pub shard_proofs: Vec<ShardProof<SC>>,
    pub leaf_challenger: &'a SC::Challenger,
    pub initial_reconstruct_challenger: SC::Challenger,
}

/// The different types of programs that can be verified by the `SP1ReduceVerifier`.
pub enum ReduceProgramType {
    /// A batch of proofs that are all SP1 Core proofs.
    Core,
    /// A batch of proofs that are all deferred proofs.
    Deferred,
    /// A batch of proofs that are reduce proofs of a higher level in the recursion tree.
    Reduce,
}

/// An input layout for the reduce verifier.
pub struct SP1ReduceMemoryLayout<
    'a,
    CoreSC: StarkGenericConfig,
    SC: StarkGenericConfig,
    A: MachineAir<SC::Val>,
> {
    pub core_vk: &'a StarkVerifyingKey<CoreSC>,
    // TODO:
    // pub deferred_vk : &'a StarkVerifyingKey<SC>,
    pub reduce_vk: &'a StarkVerifyingKey<SC>,
    pub machine: &'a StarkMachine<SC, A>,
    pub shard_proofs: Vec<ShardProof<SC>>,
    /// A type to represent the kind of program we are verifying.
    pub kind: ReduceProgramType,
}

#[derive(DslVariable, Clone)]
pub struct SP1ReduceMemoryLayoutVariable<C: Config> {
    pub core_vk: VerifyingKeyVariable<C>,
    pub reduce_vk: VerifyingKeyVariable<C>,
    pub shard_proofs: Array<C, ShardProofVariable<C>>,
    pub kind: Var<C::N>,
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
}

impl SP1RecursiveVerifier<InnerConfig, BabyBearPoseidon2> {
    pub fn setup() -> RecursionProgram<BabyBear> {
        let mut builder = Builder::<InnerConfig>::default();

        let input: SP1RecursionMemoryLayoutVariable<_> = builder.uninit();
        SP1RecursionMemoryLayout::<BabyBearPoseidon2, RiscvAir<_>>::witness(&input, &mut builder);

        builder.compile_program()
    }

    pub fn build(
        machine: &StarkMachine<BabyBearPoseidon2, RiscvAir<BabyBear>>,
    ) -> RecursionProgram<BabyBear> {
        let mut builder = Builder::<InnerConfig>::default();

        let input: SP1RecursionMemoryLayoutVariable<_> = builder.uninit();

        let pcs = TwoAdicFriPcsVariable {
            config: const_fri_config(&mut builder, default_fri_config()),
        };
        SP1RecursiveVerifier::verify(&mut builder, &pcs, machine, input);

        let mut recursive_program = builder.compile_program();
        recursive_program.instructions[0] = Instruction::dummy();
        recursive_program
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
    fn verify(
        builder: &mut Builder<C>,
        pcs: &TwoAdicFriPcsVariable<C>,
        machine: &StarkMachine<SC, A>,
        input: SP1ReduceMemoryLayoutVariable<C>,
    ) {
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
        } = input;

        // Initialize values we will commit to public outputs.

        // Start and end of program counters.
        let start_pc: Felt<_> = builder.uninit();
        let end_pc: Felt<_> = builder.uninit();

        // Start and end shard indices.
        let initial_shard: Felt<_> = builder.uninit();
        let end_shard: Felt<_> = builder.uninit();

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
            builder.eval(initial_reconstruct_challenger.clone());
        let cumulative_sum: Ext<_, _> = builder.eval(C::EF::zero().cons());
        let current_pc: Felt<_> = builder.uninit();
        // Verify proofs, validate transitions, and update accumulation variables.
        builder.range(0, shard_proofs.len()).for_each(|i, builder| {
            let proof = builder.get(&shard_proofs, i);

            // Extract public values.
            let mut pv_elements = Vec::new();
            for i in 0..PROOF_MAX_NUM_PVS {
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
            // Assert that the shard of the proof is equal to the current shard.
            builder.assert_felt_eq(current_shard, public_values.shard);

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
                chip_quotient_data,
                chip_sorted_idxs,
                preprocessed_sorted_idxs.clone(),
                prep_domains.clone(),
            );

            // Update the reconstruct challenger, cumulative sum, shard number, and program counter.
            reconstruct_challenger.observe(builder, proof.commitment.main_commit);
            for j in 0..SP1_PROOF_NUM_PV_ELTS {
                let element = builder.get(&proof.public_values, j);
                reconstruct_challenger.clone().observe(builder, element);
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

        // Initialize the public values we will commit to.
        let mut recursion_public_values_stream: [Felt<_>; RECURSIVE_PROOF_NUM_PV_ELTS] =
            array::from_fn(|_| builder.uninit());

        let recursion_public_values: &mut RecursionPublicValues<_> =
            recursion_public_values_stream.as_mut_slice().borrow_mut();

        recursion_public_values.committed_value_digest = committed_value_digest;
        recursion_public_values.deferred_proofs_digest = deferred_proofs_digest;
        recursion_public_values.start_pc = start_pc;
        recursion_public_values.next_pc = end_pc;
        recursion_public_values.start_shard = initial_shard;
        recursion_public_values.next_shard = end_shard;
        recursion_public_values.sp1_vk_digest = vk_digest;
        recursion_public_values.leaf_challenger = leaf_challenger_public_values;
        recursion_public_values.start_reconstruct_challenger = initial_challenger_public_values;
        recursion_public_values.end_reconstruct_challenger = final_challenger_public_values;
        recursion_public_values.cumulative_sum = cumulative_sum_arrray;
        recursion_public_values.start_reconstruct_deferred_digest = deferred_proofs_digest;
        recursion_public_values.end_reconstruct_deferred_digest = deferred_proofs_digest;
        recursion_public_values.exit_code = builder.eval(C::F::zero());
        recursion_public_values.is_complete = builder.eval(C::F::zero());

        let mut recursion_public_values_array =
            builder.dyn_array::<Felt<_>>(RECURSIVE_PROOF_NUM_PV_ELTS);
        for (i, value) in recursion_public_values_stream.iter().enumerate() {
            builder.set(&mut recursion_public_values_array, i, *value);
        }

        builder.commit_public_values(&recursion_public_values_array)

        // let recursion_public_values = RecursionPublicValues::<Felt<C::F>> {
        //     committed_value_digest,
        //     deferred_proofs_digest,
        //     start_pc,
        //     next_pc: end_pc,
        //     start_shard: initial_shard,
        //     next_shard: end_shard,
        //     vk_digest,
        //     leaf_challenger: leaf_challenger_public_values,
        //     start_reconstruct_challenger: initial_challenger_public_values,
        //     end_reconstruct_challenger: final_challenger_public_values,
        //     cumulative_sum: cumulative_sum_arrray,
        //     start_reconstruct_deferred_digest: deferred_proofs_digest,
        //     end_reconstruct_deferred_digest: deferred_proofs_digest,
        //     exit_code: builder.eval(C::F::zero()),
        //     is_complete: builder.eval(C::F::zero()),
        // };
    }
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
    use sp1_core::{
        io::SP1Stdin,
        stark::{Challenge, LocalProver, ProgramVerificationError},
    };
    use sp1_recursion_core::runtime::Runtime;

    use super::*;

    fn test_sp1_recursive_machine_verify(program: Program, batch_size: usize) {
        type SC = BabyBearPoseidon2;
        type F = BabyBear;
        type EF = Challenge<SC>;

        sp1_core::utils::setup_logger();

        let machine = RiscvAir::machine(SC::default());
        let (_, vk) = machine.setup(&program);
        let mut challenger = machine.config().challenger();
        let (proof, _) = sp1_core::utils::run_and_prove(program, &SP1Stdin::new(), SC::default());
        machine.verify(&vk, &proof, &mut challenger).unwrap();
        tracing::info!("Proof generated successfully");

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

        for batch in proof.shard_proofs.chunks(batch_size) {
            let proofs = batch.to_vec();

            layouts.push(SP1RecursionMemoryLayout {
                vk: &vk,
                machine: &machine,
                shard_proofs: proofs,
                leaf_challenger: &leaf_challenger,
                initial_reconstruct_challenger: reconstruct_challenger.clone(),
            });

            for proof in batch.iter() {
                reconstruct_challenger.observe(proof.commitment.main_commit);
                reconstruct_challenger
                    .observe_slice(&proof.public_values[0..machine.num_pv_elts()]);
            }
        }

        // Construct the recursion program and hint the layouts.
        let mut builder = Builder::<InnerConfig>::default();
        let input: SP1RecursionMemoryLayoutVariable<_> = builder.uninit();
        SP1RecursionMemoryLayout::<SC, RiscvAir<_>>::witness(&input, &mut builder);

        let pcs = TwoAdicFriPcsVariable {
            config: const_fri_config(&mut builder, default_fri_config()),
        };
        SP1RecursiveVerifier::verify(&mut builder, &pcs, &machine, input);

        let recursive_program = builder.compile_program();

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

        let recursive_machine = RecursionAirWideDeg3::machine(SC::default());
        let (rec_pk, rec_vk) = recursive_machine.setup(&recursive_program);

        for record in records {
            let mut recursive_challenger = recursive_machine.config().challenger();
            let rec_proof = recursive_machine.prove::<LocalProver<_, _>>(
                &rec_pk,
                record,
                &mut recursive_challenger,
            );

            let mut recursive_challenger = recursive_machine.config().challenger();
            let result = recursive_machine.verify(&rec_vk, &rec_proof, &mut recursive_challenger);

            match result {
                Ok(_) => tracing::info!("Proof verified successfully"),
                Err(ProgramVerificationError::NonZeroCumulativeSum) => {
                    tracing::info!("Proof verification failed: NonZeroCumulativeSum")
                }
                e => panic!("Proof verification failed: {:?}", e),
            }
        }
    }

    #[test]
    fn test_sp1_recursive_machine_verify_fibonacci() {
        let elf =
            include_bytes!("../../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
        test_sp1_recursive_machine_verify(Program::from(elf), 1)
    }

    #[test]
    #[ignore]
    fn test_sp1_recursive_machine_verify_tendermint() {
        let elf = include_bytes!(
            "../../../examples/tendermint-benchmark/program/elf/riscv32im-succinct-zkvm-elf"
        );
        test_sp1_recursive_machine_verify(Program::from(elf), 2)
    }
}
