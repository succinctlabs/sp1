//! A program that can reduce a set of proofs into a single proof.
#![allow(clippy::needless_range_loop)]

use array_macro::array;
use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::AbstractField;
use sp1_core::air::{Word, POSEIDON_NUM_WORDS, PV_DIGEST_NUM_WORDS};
use sp1_core::stark::PROOF_MAX_NUM_PVS;
use sp1_core::stark::{RiscvAir, ShardProof, StarkGenericConfig, VerifyingKey};
use sp1_core::utils::baby_bear_poseidon2::Challenger;
use sp1_core::utils::{inner_fri_config, sp1_fri_config, BabyBearPoseidon2Inner};
use sp1_recursion_compiler::asm::{AsmBuilder, AsmConfig};
use sp1_recursion_compiler::ir::{Array, Builder, Config, Felt, Var, Variable};
use sp1_recursion_core::air::{ChallengerPublicValues, PublicValues as RecursionPublicValues};
use sp1_recursion_core::cpu::Instruction;
use sp1_recursion_core::runtime::{RecursionProgram, DIGEST_SIZE, PERMUTATION_WIDTH};
use sp1_recursion_core::stark::RecursionAir;
use sp1_sdk::utils::BabyBearPoseidon2;
use sp1_sdk::PublicValues;

use crate::challenger::{CanObserveVariable, DuplexChallengerVariable};
use crate::fri::TwoAdicFriPcsVariable;
use crate::fri::TwoAdicMultiplicativeCosetVariable;
use crate::hints::Hintable;
use crate::stark::StarkVerifier;
use crate::types::ShardProofVariable;
use crate::types::VerifyingKeyVariable;
use crate::utils::{clone, clone_array, const_fri_config, felt2var};

type SC = BabyBearPoseidon2;
type F = <SC as StarkGenericConfig>::Val;
type EF = <SC as StarkGenericConfig>::Challenge;
type C = AsmConfig<F, EF>;
type Val = BabyBear;

fn uninit_word<V: Variable<C>>(builder: &mut AsmBuilder<F, EF>) -> Word<V> {
    Word([
        builder.uninit(),
        builder.uninit(),
        builder.uninit(),
        builder.uninit(),
    ])
}

fn assign_words<V: Variable<C>>(builder: &mut AsmBuilder<F, EF>, dst: &[Word<V>], src: &[Word<V>]) {
    debug_assert_eq!(src.len(), dst.len());
    for i in 0..src.len() {
        for j in 0..4 {
            builder.assign(dst[i][j].clone(), src[i][j].clone());
        }
    }
}

fn assert_felt_words_eq<C: Config>(
    builder: &mut Builder<C>,
    expected: &[Word<Felt<C::F>>],
    actual: &[Word<Felt<C::F>>],
) {
    debug_assert_eq!(expected.len(), actual.len());
    for i in 0..expected.len() {
        for j in 0..4 {
            builder.assert_felt_eq(expected[i][j], actual[i][j]);
        }
    }
}

fn assert_challengers_eq<C: Config>(
    builder: &mut Builder<C>,
    var: &DuplexChallengerVariable<C>,
    values: ChallengerPublicValues<Felt<C::F>>,
) {
    for i in 0..PERMUTATION_WIDTH {
        let element = builder.get(&var.sponge_state, i);
        builder.assert_felt_eq(element, values.sponge_state[i]);
    }
    let num_inputs_var = felt2var(builder, values.num_inputs);
    builder.assert_var_eq(var.nb_inputs, num_inputs_var);
    for i in 0..PERMUTATION_WIDTH {
        let element = builder.get(&var.input_buffer, i);
        builder.assert_felt_eq(element, values.input_buffer[i]);
    }
    let num_outputs_var = felt2var(builder, values.num_outputs);
    builder.assert_var_eq(var.nb_outputs, num_outputs_var);
    for i in 0..PERMUTATION_WIDTH {
        let element = builder.get(&var.output_buffer, i);
        builder.assert_felt_eq(element, values.output_buffer[i]);
    }
}

fn assign_challenger<C: Config>(
    builder: &mut Builder<C>,
    dst: &mut DuplexChallengerVariable<C>,
    values: ChallengerPublicValues<Felt<C::F>>,
) {
    for i in 0..PERMUTATION_WIDTH {
        builder.set(&mut dst.sponge_state, i, values.sponge_state[i]);
    }
    let num_inputs_var = felt2var(builder, values.num_inputs);
    builder.assign(dst.nb_inputs, num_inputs_var);
    for i in 0..PERMUTATION_WIDTH {
        builder.set(&mut dst.input_buffer, i, values.input_buffer[i]);
    }
    let num_outputs_var = felt2var(builder, values.num_outputs);
    builder.assign(dst.nb_outputs, num_outputs_var);
    for i in 0..PERMUTATION_WIDTH {
        builder.set(&mut dst.output_buffer, i, values.output_buffer[i]);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ReduceProgram;

impl ReduceProgram {
    /// The program that can reduce a set of proofs into a single proof.
    pub fn build() -> RecursionProgram<Val> {
        let mut reduce_program = Self::define(false);
        reduce_program.instructions[0] = Instruction::dummy();
        reduce_program
    }

    /// The program used for setting up the state of memory for the prover.
    pub fn setup() -> RecursionProgram<Val> {
        Self::define(true)
    }

    /// A definition for the program.
    pub fn define(setup: bool) -> RecursionProgram<Val> {
        // Initialize the sp1 and recursion maachines.
        let sp1_machine = RiscvAir::machine(BabyBearPoseidon2::default());
        let recursion_machine = RecursionAir::machine(BabyBearPoseidon2Inner::default());

        // Initialize the builder.
        let mut builder = AsmBuilder::<F, EF>::default();

        // Initialize the sp1 and recursion configs as constants..
        let sp1_config = const_fri_config(&mut builder, sp1_fri_config());
        let recursion_config = const_fri_config(&mut builder, inner_fri_config());
        let sp1_pcs = TwoAdicFriPcsVariable { config: sp1_config };
        let recursion_pcs = TwoAdicFriPcsVariable {
            config: recursion_config,
        };

        // Allocate empty space on the stack for the inputs.
        //
        // In the case where setup is not true, the values on the stack will all be witnessed
        // with the appropriate values using the hinting API.
        let is_recursive_flags: Array<_, Var<_>> = builder.uninit();
        let sorted_indices: Array<_, Array<_, Var<_>>> = builder.uninit();
        let verify_start_challenger: DuplexChallengerVariable<_> = builder.uninit();
        let mut reconstruct_challenger: DuplexChallengerVariable<_> = builder.uninit();
        let prep_sorted_indices: Array<_, Var<_>> = builder.uninit();
        let prep_domains: Array<_, TwoAdicMultiplicativeCosetVariable<_>> = builder.uninit();
        let recursion_prep_sorted_indices: Array<_, Var<_>> = builder.uninit();
        let recursion_prep_domains: Array<_, TwoAdicMultiplicativeCosetVariable<_>> =
            builder.uninit();
        let sp1_vk: VerifyingKeyVariable<_> = builder.uninit();
        let recursion_vk: VerifyingKeyVariable<_> = builder.uninit();
        let proofs: Array<_, ShardProofVariable<_>> = builder.uninit();
        let mut reconstruct_deferred_digest: Array<_, Felt<_>> = builder.uninit();
        let deferred_sorted_indices: Array<_, Array<_, Var<_>>> = builder.uninit();
        let num_deferred_proofs: Var<_> = builder.uninit();
        let deferred_proofs: Array<_, ShardProofVariable<_>> = builder.uninit();
        let deferred_vks: Array<_, VerifyingKeyVariable<_>> = builder.uninit();
        let is_complete: Var<_> = builder.uninit();

        // Setup the memory for the prover.
        //
        // If the program is being setup, we need to witness the inputs using the hinting API
        // and setup the correct state of memory.
        if setup {
            Vec::<usize>::witness(&is_recursive_flags, &mut builder);
            Vec::<Vec<usize>>::witness(&sorted_indices, &mut builder);
            DuplexChallenger::witness(&verify_start_challenger, &mut builder);
            DuplexChallenger::witness(&reconstruct_challenger, &mut builder);
            Vec::<usize>::witness(&prep_sorted_indices, &mut builder);
            Vec::<TwoAdicMultiplicativeCoset<BabyBear>>::witness(&prep_domains, &mut builder);
            Vec::<usize>::witness(&recursion_prep_sorted_indices, &mut builder);
            Vec::<TwoAdicMultiplicativeCoset<BabyBear>>::witness(
                &recursion_prep_domains,
                &mut builder,
            );
            VerifyingKey::<SC>::witness(&sp1_vk, &mut builder);
            VerifyingKey::<SC>::witness(&recursion_vk, &mut builder);

            let num_proofs = is_recursive_flags.len();
            let mut proofs_target = builder.dyn_array(num_proofs);
            builder.range(0, num_proofs).for_each(|i, builder| {
                let proof = ShardProof::<SC>::read(builder);
                builder.set(&mut proofs_target, i, proof);
            });
            builder.assign(proofs.clone(), proofs_target);

            Vec::<BabyBear>::witness(&reconstruct_deferred_digest, &mut builder);
            Vec::<Vec<usize>>::witness(&deferred_sorted_indices, &mut builder);
            Vec::<ShardProof<SC>>::witness(&deferred_proofs, &mut builder);
            let num_deferred_proofs_var = deferred_proofs.len();
            builder.assign(num_deferred_proofs, num_deferred_proofs_var);
            let mut deferred_vks_target = builder.dyn_array(num_proofs);
            builder
                .range(0, num_deferred_proofs)
                .for_each(|i, builder| {
                    let vk = VerifyingKey::<SC>::read(builder);
                    builder.set(&mut deferred_vks_target, i, vk);
                });
            builder.assign(deferred_vks.clone(), deferred_vks_target);
            usize::witness(&is_complete, &mut builder);

            return builder.compile_program();
        }

        let num_proofs = is_recursive_flags.len();
        let zero: Var<_> = builder.constant(F::zero());
        let zero_felt: Felt<_> = builder.constant(F::zero());
        let one: Var<_> = builder.constant(F::one());
        let one_felt: Felt<_> = builder.constant(F::one());

        // Setup the recursive challenger.
        builder.cycle_tracker("stage-b-setup-recursion-challenger");
        let mut recursion_challenger = DuplexChallengerVariable::new(&mut builder);
        for j in 0..DIGEST_SIZE {
            let element = builder.get(&recursion_vk.commitment, j);
            recursion_challenger.observe(&mut builder, element);
        }
        recursion_challenger.observe(&mut builder, recursion_vk.pc_start);
        builder.cycle_tracker("stage-b-setup-recursion-challenger");

        // Global variables that will be commmitted to at the end.
        let global_committed_values_digest: [Word<Felt<_>>; PV_DIGEST_NUM_WORDS] =
            array![_ => uninit_word(&mut builder); PV_DIGEST_NUM_WORDS];
        let global_deferred_proofs_digest: [Felt<_>; POSEIDON_NUM_WORDS] =
            array![_ => builder.uninit(); POSEIDON_NUM_WORDS];
        let global_start_pc: Felt<_> = builder.uninit();
        let global_next_pc: Felt<_> = builder.uninit();
        let global_exit_code: Felt<_> = builder.uninit();
        let global_start_shard: Felt<_> = builder.uninit();
        let global_end_shard: Felt<_> = builder.uninit();
        let start_reconstruct_challenger = clone(&mut builder, &reconstruct_challenger);
        let start_reconstruct_deferred_digest =
            clone_array(&mut builder, &reconstruct_deferred_digest);

        // Previous proof's values.
        let prev_next_pc: Felt<_> = builder.uninit();
        let prev_end_shard: Felt<_> = builder.uninit();

        // Verify sp1 and recursive proofs.
        builder.range(0, num_proofs).for_each(|i, builder| {
            let proof = builder.get(&proofs, i);
            let sorted_indices = builder.get(&sorted_indices, i);
            let is_recursive = builder.get(&is_recursive_flags, i);

            // Verify shard transition.

            builder.if_eq(is_recursive, zero).then_or_else(
                // Handle the case where the proof is a sp1 proof.
                |builder| {
                    // Clone the variable pointer to reconstruct_challenger.
                    let reconstruct_challenger = reconstruct_challenger.clone();
                    // Extract public values.
                    let mut pv_elements = Vec::new();
                    for i in 0..PROOF_MAX_NUM_PVS {
                        let element = builder.get(&proof.public_values, i);
                        pv_elements.push(element);
                    }
                    let pv = PublicValues::<Word<Felt<_>>, Felt<_>>::from_vec(pv_elements);

                    // Verify shard transitions.
                    let prev_end_shard_plus_one: Felt<_> = builder.eval(prev_end_shard + one_felt);

                    builder.if_eq(i, one).then_or_else(
                        // First proof: initialize the global values.
                        |builder| {
                            assign_words(
                                builder,
                                &global_committed_values_digest,
                                &pv.committed_value_digest,
                            );
                            for j in 0..POSEIDON_NUM_WORDS {
                                builder.assign(
                                    global_deferred_proofs_digest[j],
                                    pv.deferred_proofs_digest[j],
                                );
                            }
                            builder.assign(global_start_shard, pv.shard);
                            builder.assign(global_exit_code, pv.exit_code);
                        },
                        // Non-first proofs: verify global values are same and transitions are valid.
                        |builder| {
                            // Assert that digests and exit code are the same
                            assert_felt_words_eq(
                                builder,
                                &global_committed_values_digest,
                                &pv.committed_value_digest,
                            );
                            for j in 0..POSEIDON_NUM_WORDS {
                                builder.assert_felt_eq(
                                    global_deferred_proofs_digest[j],
                                    pv.deferred_proofs_digest[j],
                                );
                            }
                            builder.assert_felt_eq(global_exit_code, pv.exit_code);

                            // Shard should be previous end shard + 1.
                            builder.assert_felt_eq(pv.shard, prev_end_shard_plus_one);
                            // Start pc should be equal to next_pc declared in previous proof.
                            builder.assert_felt_eq(pv.start_pc, prev_next_pc);

                            builder.if_eq(i, num_proofs - one).then_or_else(
                                // Set global end variables.
                                |builder| {
                                    builder.assign(global_end_shard, pv.shard);
                                    builder.assign(global_next_pc, pv.next_pc);
                                },
                                // If it's not the last proof, next_pc should not be 0.
                                |builder| {
                                    builder.assert_felt_ne(pv.next_pc, zero_felt);
                                },
                            );
                        },
                    );
                    builder.assign(prev_next_pc, pv.next_pc);
                    builder.assign(prev_end_shard, pv.shard);

                    // Need to convert the shard as a felt to a variable, since `if_eq` only handles
                    // variables.
                    let shard_f = pv.shard;
                    let shard = felt2var(builder, shard_f);

                    // Handle the case where the shard is the first shard.
                    builder.if_eq(shard, one).then(|builder| {
                        // Start pc should be sp1_vk.pc_start
                        builder.assert_felt_eq(pv.start_pc, sp1_vk.pc_start);

                        let mut reconstruct_challenger = reconstruct_challenger.clone();
                        // Initialize the reconstruct challenger from empty challenger.
                        let empty_challenger = DuplexChallengerVariable::new(builder);
                        builder.assign(reconstruct_challenger.clone(), empty_challenger);
                        reconstruct_challenger.observe(builder, sp1_vk.commitment.clone());
                        reconstruct_challenger.observe(builder, sp1_vk.pc_start);
                    });

                    // Observe current proof commit and public values into reconstruct challenger.
                    for j in 0..DIGEST_SIZE {
                        let element = builder.get(&proof.commitment.main_commit, j);
                        reconstruct_challenger.clone().observe(builder, element);
                    }

                    // TODO: fix public values observe
                    // let public_values = proof.public_values.to_vec(builder);
                    // reconstruct_challenger.observe_slice(builder, &public_values);

                    // Verify proof with copy of witnessed challenger.
                    let mut current_challenger = verify_start_challenger.copy(builder);

                    // Verify the shard.
                    StarkVerifier::<C, BabyBearPoseidon2>::verify_shard(
                        builder,
                        &sp1_vk.clone(),
                        &sp1_pcs,
                        &sp1_machine,
                        &mut current_challenger,
                        &proof,
                        sorted_indices.clone(),
                        prep_sorted_indices.clone(),
                        prep_domains.clone(),
                    );
                },
                // Handle the case where the proof is a recursive proof.
                |builder| {
                    let mut reconstruct_challenger = reconstruct_challenger.clone();
                    let mut pv_elements = Vec::new();
                    for i in 0..PROOF_MAX_NUM_PVS {
                        let element = builder.get(&proof.public_values, i);
                        pv_elements.push(element);
                    }
                    let pv = RecursionPublicValues::<Felt<_>>::from_vec(pv_elements);

                    // Verify shard transitions.
                    let prev_end_shard_plus_one: Felt<_> = builder.eval(prev_end_shard + one_felt);
                    builder.if_eq(i, one).then_or_else(
                        // First proof: initialize the global values.
                        |builder| {
                            assign_words(
                                builder,
                                &global_committed_values_digest,
                                &pv.committed_value_digest,
                            );
                            for j in 0..POSEIDON_NUM_WORDS {
                                builder.assign(
                                    global_deferred_proofs_digest[j],
                                    pv.deferred_proofs_digest[j],
                                );
                            }
                            builder.assign(global_start_shard, pv.start_shard);
                            builder.assign(global_exit_code, pv.exit_code);
                        },
                        // Non-first proofs: verify global values are same and transitions are valid.
                        |builder| {
                            // Assert that digests and exit code are the same
                            assert_felt_words_eq(
                                builder,
                                &global_committed_values_digest,
                                &pv.committed_value_digest,
                            );
                            for j in 0..POSEIDON_NUM_WORDS {
                                builder.assert_felt_eq(
                                    global_deferred_proofs_digest[j],
                                    pv.deferred_proofs_digest[j],
                                );
                            }
                            builder.assert_felt_eq(global_exit_code, pv.exit_code);

                            // Shard should be previous end shard + 1.
                            builder.assert_felt_eq(pv.start_shard, prev_end_shard_plus_one);
                            // Start pc should be equal to next_pc declared in previous proof.
                            builder.assert_felt_eq(pv.start_pc, prev_next_pc);

                            builder.if_eq(i, num_proofs - one).then_or_else(
                                // Set global end variables.
                                |builder| {
                                    builder.assign(global_end_shard, pv.end_shard);
                                    builder.assign(global_next_pc, pv.next_pc);
                                },
                                // If it's not the last proof, next_pc should not be 0.
                                |builder| {
                                    builder.assert_felt_ne(pv.next_pc, zero_felt);
                                },
                            );
                        },
                    );
                    builder.assign(prev_next_pc, pv.next_pc);
                    builder.assign(prev_end_shard, pv.end_shard);

                    // Assert that the current reconstruct_challenger is the same as the proof's
                    // start_reconstruct_challenger, then fast-forward to end_reconstruct_challenger.
                    assert_challengers_eq(
                        builder,
                        &reconstruct_challenger,
                        pv.start_reconstruct_challenger,
                    );
                    assign_challenger(
                        builder,
                        &mut reconstruct_challenger,
                        pv.end_reconstruct_challenger,
                    );

                    // Assert that the current deferred_proof_digest is the same as the proof's
                    // start_reconstruct_deferred_digest, then fast-forward to end digest.
                    for j in 0..DIGEST_SIZE {
                        let element = builder.get(&reconstruct_deferred_digest, j);
                        builder.assert_felt_eq(element, pv.start_reconstruct_deferred_digest[j]);
                    }
                    for j in 0..DIGEST_SIZE {
                        builder.set(
                            &mut reconstruct_deferred_digest,
                            j,
                            pv.end_reconstruct_deferred_digest[j],
                        );
                    }

                    // Assert that sp1_vk, recursion_vk, and verify_start_challenger are the same.
                    for j in 0..DIGEST_SIZE {
                        let element = builder.get(&sp1_vk.commitment, j);
                        builder.assert_felt_eq(element, pv.sp1_vk_commit[j]);
                    }
                    for j in 0..DIGEST_SIZE {
                        let element = builder.get(&recursion_vk.commitment, j);
                        builder.assert_felt_eq(element, pv.recursion_vk_commit[j]);
                    }
                    assert_challengers_eq(
                        builder,
                        &verify_start_challenger,
                        pv.verify_start_challenger,
                    );

                    // Setup the recursive challenger to use for verifying.
                    let mut current_challenger = recursion_challenger.copy(builder);
                    for j in 0..DIGEST_SIZE {
                        let element = builder.get(&proof.commitment.main_commit, j);
                        current_challenger.observe(builder, element);
                    }
                    builder.range(0, DIGEST_SIZE).for_each(|j, builder| {
                        let element = builder.get(&proof.public_values, j);
                        current_challenger.observe(builder, element);
                    });

                    // Verify the shard.
                    StarkVerifier::<C, BabyBearPoseidon2Inner>::verify_shard(
                        builder,
                        &recursion_vk.clone(),
                        &recursion_pcs,
                        &recursion_machine,
                        &mut current_challenger,
                        &proof,
                        sorted_indices.clone(),
                        recursion_prep_sorted_indices.clone(),
                        recursion_prep_domains.clone(),
                    );
                },
            );
        });

        // Verify deferred proofs and acculumate to deferred proofs digest.
        let _pre_deferred_proof_digest = clone(&mut builder, &reconstruct_deferred_digest);
        for j in 0..DIGEST_SIZE {
            let val = builder.get(&reconstruct_deferred_digest, j);
            builder.print_f(val);
        }
        builder
            .range(0, num_deferred_proofs)
            .for_each(|i, builder| {
                let proof = builder.get(&deferred_proofs, i);
                let vk = builder.get(&deferred_vks, i);
                let sorted_indices = builder.get(&deferred_sorted_indices, i);
                let mut challenger = recursion_challenger.copy(builder);
                for j in 0..DIGEST_SIZE {
                    let element = builder.get(&proof.commitment.main_commit, j);
                    challenger.observe(builder, element);
                }
                builder.range(0, DIGEST_SIZE).for_each(|j, builder| {
                    let element = builder.get(&proof.public_values, j);
                    challenger.observe(builder, element);
                });

                // Verify the shard.
                StarkVerifier::<C, BabyBearPoseidon2Inner>::verify_shard(
                    builder,
                    &recursion_vk.clone(),
                    &recursion_pcs,
                    &recursion_machine,
                    &mut challenger,
                    &proof,
                    sorted_indices.clone(),
                    recursion_prep_sorted_indices.clone(),
                    recursion_prep_domains.clone(),
                );

                // TODO: verify inner proof's public values (it must be complete)
                // Update deferred proof digest
                // poseidon2( prev_digest || vk.commit || proof.pv_digest )
                let mut poseidon_inputs = builder.array(24);
                builder.range(0, 8).for_each(|j, builder| {
                    let element = builder.get(&reconstruct_deferred_digest, j);
                    builder.set(&mut poseidon_inputs, j, element);
                });
                builder.range(0, 8).for_each(|j, builder| {
                    let input_index: Var<_> = builder.eval(j + F::from_canonical_u32(8));
                    let element = builder.get(&vk.commitment, j);
                    builder.set(&mut poseidon_inputs, input_index, element);
                });
                builder.range(0, 8).for_each(|j, builder| {
                    let input_index: Var<_> = builder.eval(j + F::from_canonical_u32(16));
                    let element = builder.get(&proof.public_values, j);
                    builder.set(&mut poseidon_inputs, input_index, element);
                });
                let new_digest = builder.poseidon2_hash(&poseidon_inputs);
                builder.assign(reconstruct_deferred_digest.clone(), new_digest);
                for j in 0..DIGEST_SIZE {
                    let val = builder.get(&reconstruct_deferred_digest, j);
                    builder.print_f(val);
                }
            });

        // Proof is complete only if:
        // 1) Proof begins at shard == 1.
        // 2) Execution has halted (next_pc == 0).
        // 3) start_reconstruct_challenger == empty challenger.
        // 4) end_reconstruct_challenger == verify_start_challenger.
        // 5) start_reconstruct_deferred_digest == 0.
        // 6) end_reconstruct_deferred_digest == deferred_proofs_digest.
        // Proof is complete only if start_pc == sp1_vk.start_pc && start_shard == 1 && next_pc == 0
        // && start_reconstruct_challenger == empty && end_reconstruct_challenger == verify_start_challenger
        // && start_reconstruct_deferred_digest == 0 && end_reconstruct_deferred_digest == deferred_proofs_digest
        let empty_challenger = DuplexChallengerVariable::new(&mut builder);
        let global_start_shard_var = felt2var(&mut builder, global_start_shard);
        let global_next_pc_var = felt2var(&mut builder, global_next_pc);
        builder.if_eq(is_complete, one).then(|builder| {
            builder.assert_var_eq(global_start_shard_var, one);
            builder.assert_var_eq(global_next_pc_var, zero);
            start_reconstruct_challenger.assert_eq(builder, &empty_challenger);
            reconstruct_challenger.assert_eq(builder, &verify_start_challenger);
            for j in 0..DIGEST_SIZE {
                let element = builder.get(&start_reconstruct_deferred_digest, j);
                builder.assert_felt_eq(element, zero_felt);
            }
            for j in 0..DIGEST_SIZE {
                let element = builder.get(&reconstruct_deferred_digest, j);
                builder.assert_felt_eq(element, global_deferred_proofs_digest[j]);
            }
        });

        // Public values:
        // (
        //     committed_values_digest, (equal)x
        //     deferred_proofs_digest, (equal)x
        //     start_pc, (equals prev next_pc)
        //     next_pc,
        //     exit_code, (equal)x
        //     start_shard, (equals prev end_shard + 1)
        //     end_shard,
        //     start_reconstruct_challenger, (equals current state)x
        //     end_reconstruct_challenger, (use as new state)x
        //     start_reconstruct_deferred_digest, (equals current state)x
        //     end_reconstruct_deferred_digest, (use as new state)x
        //     sp1_vk, (equal)x
        //     recursion_vk, (equal)x
        //     verify_start_challenger, (equal)x
        //     is_complete,
        // )
        // Note we still need to check that verify_start_challenger matches final reconstruct_challenger
        // after observing pv_digest at the end.

        // let start_pc = builder.get(&start_pcs, zero);
        // let start_shard = builder.get(&start_shards, zero);
        // let last_idx: Var<_> = builder.eval(num_proofs - one);
        // let next_pc = builder.get(&next_pcs, last_idx);
        // let next_shard = builder.get(&next_shards, last_idx);
        // builder.commit_public_value(start_pc);
        // builder.commit_public_value(start_shard);
        // builder.commit_public_value(next_pc);
        // builder.commit_public_value(next_shard);

        builder.compile_program()
    }
}
