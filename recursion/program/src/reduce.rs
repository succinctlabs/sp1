use std::time::Instant;

use crate::challenger::CanObserveVariable;
use crate::challenger::DuplexChallengerVariable;
use crate::fri::types::FriConfigVariable;
use crate::fri::TwoAdicFriPcsVariable;
use crate::fri::TwoAdicMultiplicativeCosetVariable;
use crate::hints::Hintable;
use crate::stark::StarkVerifier;
use crate::types::ShardProofVariable;
use crate::types::VerifyingKeyVariable;
use p3_baby_bear::BabyBear;
use p3_baby_bear::DiffusionMatrixBabybear;
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::extension::BinomialExtensionField;
use p3_field::AbstractField;
use p3_field::Field;
use p3_field::TwoAdicField;
use p3_fri::FriConfig;
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon2::Poseidon2;
use p3_poseidon2::Poseidon2ExternalMatrixGeneral;
use p3_symmetric::PaddingFreeSponge;
use p3_symmetric::TruncatedPermutation;
use sp1_core::air::Word;
use sp1_core::stark::ShardProof;
use sp1_core::stark::VerifyingKey;
use sp1_core::stark::PROOF_MAX_NUM_PVS;
use sp1_core::stark::{RiscvAir, StarkGenericConfig};
use sp1_core::utils::inner_fri_config;
use sp1_core::utils::sp1_fri_config;
use sp1_core::utils::BabyBearPoseidon2Inner;
use sp1_recursion_compiler::asm::AsmBuilder;
use sp1_recursion_compiler::asm::AsmConfig;
use sp1_recursion_compiler::ir::Array;
use sp1_recursion_compiler::ir::Builder;
use sp1_recursion_compiler::ir::Felt;
use sp1_recursion_compiler::ir::MemVariable;
use sp1_recursion_compiler::ir::Var;
use sp1_recursion_core::air::PublicValues as RecursionPublicValues;
use sp1_recursion_core::cpu::Instruction;
use sp1_recursion_core::runtime::RecursionProgram;
use sp1_recursion_core::runtime::DIGEST_SIZE;
use sp1_recursion_core::stark::RecursionAir;
use sp1_sdk::utils::BabyBearPoseidon2;
use sp1_sdk::PublicValues;

type SC = BabyBearPoseidon2;
type F = <SC as StarkGenericConfig>::Val;
type EF = <SC as StarkGenericConfig>::Challenge;
type C = AsmConfig<F, EF>;

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type Perm = Poseidon2<Val, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabybear, 16, 7>;
type Hash = PaddingFreeSponge<Perm, 16, 8, 8>;
type Compress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs =
    FieldMerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, Hash, Compress, 8>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type RecursionConfig = AsmConfig<Val, Challenge>;
type RecursionBuilder = Builder<RecursionConfig>;

pub fn const_fri_config(
    builder: &mut RecursionBuilder,
    config: FriConfig<ChallengeMmcs>,
) -> FriConfigVariable<RecursionConfig> {
    let two_addicity = Val::TWO_ADICITY;
    let mut generators = builder.dyn_array(two_addicity);
    let mut subgroups = builder.dyn_array(two_addicity);
    for i in 0..two_addicity {
        let constant_generator = Val::two_adic_generator(i);
        builder.set(&mut generators, i, constant_generator);

        let constant_domain = TwoAdicMultiplicativeCoset {
            log_n: i,
            shift: Val::one(),
        };
        let domain_value: TwoAdicMultiplicativeCosetVariable<_> = builder.constant(constant_domain);
        builder.set(&mut subgroups, i, domain_value);
    }
    FriConfigVariable {
        log_blowup: config.log_blowup,
        num_queries: config.num_queries,
        proof_of_work_bits: config.proof_of_work_bits,
        subgroups,
        generators,
    }
}

fn clone<T: MemVariable<C>>(builder: &mut RecursionBuilder, var: &T) -> T {
    let mut arr = builder.dyn_array(1);
    builder.set(&mut arr, 0, var.clone());
    builder.get(&arr, 0)
}

fn felt_to_var(builder: &mut RecursionBuilder, felt: Felt<BabyBear>) -> Var<BabyBear> {
    let bits = builder.num2bits_f(felt);
    builder.bits2num_v(&bits)
}

/// Builds a reduce program. Returns a setup program and a reduce program, where the setup one is
/// used to initialize witness variables without costing cycles.
pub fn build_reduce_program() -> (RecursionProgram<Val>, RecursionProgram<Val>) {
    let reduce_setup_program = build_reduce_program_setup(true);
    let mut reduce_program = build_reduce_program_setup(false);
    reduce_program.instructions[0] = Instruction::new(
        sp1_recursion_core::runtime::Opcode::ADD,
        BabyBear::zero(),
        [BabyBear::zero(); 4],
        [BabyBear::zero(); 4],
        BabyBear::zero(),
        BabyBear::zero(),
        false,
        false,
        "".to_string(),
    );
    (reduce_setup_program, reduce_program)
}

fn build_reduce_program_setup(setup: bool) -> RecursionProgram<Val> {
    let sp1_machine = RiscvAir::machine(BabyBearPoseidon2::default());
    let recursion_machine = RecursionAir::machine(BabyBearPoseidon2Inner::default());

    let time = Instant::now();
    let mut builder = AsmBuilder::<F, EF>::default();
    let sp1_config = const_fri_config(&mut builder, sp1_fri_config());
    // TODO: this config may change
    let recursion_config = const_fri_config(&mut builder, inner_fri_config());
    let sp1_pcs = TwoAdicFriPcsVariable { config: sp1_config };
    let recursion_pcs = TwoAdicFriPcsVariable {
        config: recursion_config,
    };

    // 1) Allocate inputs to the stack.
    builder.cycle_tracker("stage-a-setup-inputs");
    let is_recursive_flags: Array<_, Var<_>> = builder.uninit();
    let sorted_indices: Array<_, Array<_, Var<_>>> = builder.uninit();
    let sp1_challenger: DuplexChallengerVariable<_> = builder.uninit();
    let mut reconstruct_challenger: DuplexChallengerVariable<_> = builder.uninit();
    let prep_sorted_indices: Array<_, Var<_>> = builder.uninit();
    let prep_domains: Array<_, TwoAdicMultiplicativeCosetVariable<_>> = builder.uninit();
    let recursion_prep_sorted_indices: Array<_, Var<_>> = builder.uninit();
    let recursion_prep_domains: Array<_, TwoAdicMultiplicativeCosetVariable<_>> = builder.uninit();
    let sp1_vk: VerifyingKeyVariable<_> = builder.uninit();
    let recursion_vk: VerifyingKeyVariable<_> = builder.uninit();
    let start_pcs: Array<_, Felt<_>> = builder.uninit();
    let next_pcs: Array<_, Felt<_>> = builder.uninit();
    let start_shards: Array<_, Felt<_>> = builder.uninit();
    let next_shards: Array<_, Felt<_>> = builder.uninit();
    let proofs: Array<_, ShardProofVariable<_>> = builder.uninit();
    let deferred_proof_digest: Array<_, Felt<_>> = builder.uninit();
    let deferred_sorted_indices: Array<_, Array<_, Var<_>>> = builder.uninit();
    let num_deferred_proofs: Var<_> = builder.uninit();
    let deferred_proofs: Array<_, ShardProofVariable<_>> = builder.uninit();
    let deferred_vks: Array<_, VerifyingKeyVariable<_>> = builder.uninit();
    // 2) Witness the inputs.
    if setup {
        Vec::<usize>::witness(&is_recursive_flags, &mut builder);
        Vec::<Vec<usize>>::witness(&sorted_indices, &mut builder);
        DuplexChallenger::witness(&sp1_challenger, &mut builder);
        DuplexChallenger::witness(&reconstruct_challenger, &mut builder);
        Vec::<usize>::witness(&prep_sorted_indices, &mut builder);
        Vec::<TwoAdicMultiplicativeCoset<BabyBear>>::witness(&prep_domains, &mut builder);
        Vec::<usize>::witness(&recursion_prep_sorted_indices, &mut builder);
        Vec::<TwoAdicMultiplicativeCoset<BabyBear>>::witness(&recursion_prep_domains, &mut builder);
        VerifyingKey::<SC>::witness(&sp1_vk, &mut builder);
        VerifyingKey::<SC>::witness(&recursion_vk, &mut builder);
        // Read proofs
        Vec::<Val>::witness(&start_pcs, &mut builder);
        Vec::<Val>::witness(&next_pcs, &mut builder);
        Vec::<Val>::witness(&start_shards, &mut builder);
        Vec::<Val>::witness(&next_shards, &mut builder);
        let num_proofs = is_recursive_flags.len();
        let mut proofs_target = builder.dyn_array(num_proofs);
        builder.range(0, num_proofs).for_each(|i, builder| {
            let proof = ShardProof::<SC>::read(builder);
            builder.set(&mut proofs_target, i, proof);
        });
        builder.assign(proofs.clone(), proofs_target);
        // Read deferred proof digest
        Vec::<BabyBear>::witness(&deferred_proof_digest, &mut builder);
        // Read deferred sorted indices
        Vec::<Vec<usize>>::witness(&deferred_sorted_indices, &mut builder);
        // Read deferred proofs
        Vec::<ShardProof<SC>>::witness(&deferred_proofs, &mut builder);
        // Read deferred vks
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

        // Compile the program up to this point.
        return builder.compile_program();
    }

    let num_proofs = is_recursive_flags.len();
    let _pre_reconstruct_challenger = clone(&mut builder, &reconstruct_challenger);
    let zero: Var<_> = builder.constant(F::zero());
    let zero_felt: Felt<_> = builder.constant(F::zero());
    let one: Var<_> = builder.constant(F::one());
    let one_felt: Felt<_> = builder.constant(F::one());
    builder.cycle_tracker("stage-a-setup-inputs");

    // Setup recursion challenger
    builder.cycle_tracker("stage-b-setup-recursion-challenger");
    let mut recursion_challenger = DuplexChallengerVariable::new(&mut builder);
    for j in 0..DIGEST_SIZE {
        let element = builder.get(&recursion_vk.commitment, j);
        recursion_challenger.observe(&mut builder, element);
    }
    recursion_challenger.observe(&mut builder, recursion_vk.pc_start);
    builder.cycle_tracker("stage-b-setup-recursion-challenger");

    // Verify sp1 and recursive proofs
    let expected_start_pc = builder.get(&start_pcs, zero);
    let expected_start_shard = builder.get(&start_shards, zero);

    builder.range(0, num_proofs).for_each(|i, builder| {
        let proof = builder.get(&proofs, i);
        let sorted_indices = builder.get(&sorted_indices, i);
        let is_recursive = builder.get(&is_recursive_flags, i);

        let shard_start_pc = builder.get(&start_pcs, i);
        let shard_next_pc = builder.get(&next_pcs, i);
        let shard_start_shard = builder.get(&start_shards, i);
        let shard_next_shard = builder.get(&next_shards, i);

        // Verify shard transition
        builder.assert_felt_eq(expected_start_pc, shard_start_pc);
        builder.assign(expected_start_pc, shard_next_pc);
        builder.assert_felt_eq(expected_start_shard, shard_start_shard);
        builder.assign(expected_start_shard, shard_next_shard);

        builder.if_eq(is_recursive, zero).then_or_else(
            // Non-recursive proof
            |builder| {
                let mut pv_elements = Vec::new();
                for i in 0..PROOF_MAX_NUM_PVS {
                    let element = builder.get(&proof.public_values, i);
                    pv_elements.push(element);
                }

                let pv = PublicValues::<Word<Felt<_>>, Felt<_>>::from_vec(pv_elements);

                // Verify witness data
                builder.assert_felt_eq(shard_start_pc, pv.start_pc);
                builder.assert_felt_eq(shard_next_pc, pv.next_pc);
                builder.assert_felt_eq(shard_start_shard, pv.shard);
                let pv_shard_plus_one: Felt<_> = builder.eval(pv.shard + one_felt);

                let pv_next_pc = felt_to_var(builder, pv.next_pc);
                builder.if_eq(pv_next_pc, zero).then_or_else(
                    |builder| {
                        builder.assert_felt_eq(shard_next_shard, zero_felt);
                    },
                    |builder| {
                        builder.assert_felt_eq(shard_next_shard, pv_shard_plus_one);
                    },
                );

                // Need to convert the shard as a felt to a variable, since `if_eq` only handles variables.
                let shard_f = pv.shard;
                let shard = felt_to_var(builder, shard_f);

                // First shard logic
                builder.if_eq(shard, one).then(|builder| {
                    // Initialize the current challenger
                    let empty_challenger = DuplexChallengerVariable::new(builder);
                    builder.assign(reconstruct_challenger.clone(), empty_challenger);
                    reconstruct_challenger.observe(builder, sp1_vk.commitment.clone());
                    reconstruct_challenger.observe(builder, sp1_vk.pc_start);
                });

                // Observe current proof commit and public values into reconstruct challenger
                for j in 0..DIGEST_SIZE {
                    let element = builder.get(&proof.commitment.main_commit, j);
                    reconstruct_challenger.observe(builder, element);
                }
                // TODO: fix public values observe
                // let public_values = proof.public_values.to_vec(builder);
                // reconstruct_challenger.observe_slice(builder, &public_values);

                // Verify proof with copy of witnessed challenger
                let mut current_challenger = sp1_challenger.as_clone(builder);
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
            // Recursive proof
            |builder| {
                let mut pv_elements = Vec::new();
                for i in 0..PROOF_MAX_NUM_PVS {
                    let element = builder.get(&proof.public_values, i);
                    pv_elements.push(element);
                }

                let proof_pv = RecursionPublicValues::<Felt<_>>::from_vec(pv_elements);

                let mut pv = builder.array(4);
                builder.set(&mut pv, 0, shard_start_pc);
                builder.set(&mut pv, 1, shard_start_shard);
                builder.set(&mut pv, 2, shard_next_pc);
                builder.set(&mut pv, 3, shard_next_shard);

                let pv_digest = builder.poseidon2_hash(&pv);

                for j in 0..DIGEST_SIZE {
                    let expected_digest_element = proof_pv.committed_value_digest[j];
                    let digest_element = builder.get(&pv_digest, j);
                    builder.assert_felt_eq(expected_digest_element, digest_element);
                }

                // Build recursion challenger
                let mut current_challenger = recursion_challenger.as_clone(builder);
                for j in 0..DIGEST_SIZE {
                    let element = builder.get(&proof.commitment.main_commit, j);
                    current_challenger.observe(builder, element);
                }
                builder.range(0, DIGEST_SIZE).for_each(|j, builder| {
                    let element = builder.get(&proof.public_values, j);
                    current_challenger.observe(builder, element);
                });
                // Verify the proof
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

    // Verify deferred proofs and acculumate to deferred proofs digest
    let _pre_deferred_proof_digest = clone(&mut builder, &deferred_proof_digest);
    for j in 0..DIGEST_SIZE {
        let val = builder.get(&deferred_proof_digest, j);
        builder.print_f(val);
    }
    builder
        .range(0, num_deferred_proofs)
        .for_each(|i, builder| {
            let proof = builder.get(&deferred_proofs, i);
            let vk = builder.get(&deferred_vks, i);
            let sorted_indices = builder.get(&deferred_sorted_indices, i);
            let mut challenger = recursion_challenger.as_clone(builder);
            for j in 0..DIGEST_SIZE {
                let element = builder.get(&proof.commitment.main_commit, j);
                challenger.observe(builder, element);
            }
            builder.range(0, DIGEST_SIZE).for_each(|j, builder| {
                let element = builder.get(&proof.public_values, j);
                challenger.observe(builder, element);
            });
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
                let element = builder.get(&deferred_proof_digest, j);
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
            builder.assign(deferred_proof_digest.clone(), new_digest);
            for j in 0..DIGEST_SIZE {
                let val = builder.get(&deferred_proof_digest, j);
                builder.print_f(val);
            }
        });

    // Public values:
    // (
    //     committed_values_digest,
    //     start_pc,
    //     next_pc,
    //     exit_code,
    //     reconstruct_challenger,
    //     pre_reconstruct_challenger,
    //     verify_start_challenger,
    //     recursion_vk,
    //     start_deferred_proof_digest,
    //     end_deferred_proof_digest,
    // )
    // Note we still need to check that verify_start_challenger matches final reconstruct_challenger
    // after observing pv_digest at the end.

    let start_pc = builder.get(&start_pcs, zero);
    let start_shard = builder.get(&start_shards, zero);
    builder.write_public_value(start_pc);
    builder.write_public_value(start_shard);

    let last_idx: Var<_> = builder.eval(num_proofs - one);
    let next_pc = builder.get(&next_pcs, last_idx);
    let next_shard = builder.get(&next_shards, last_idx);
    builder.write_public_value(next_pc);
    builder.write_public_value(next_shard);

    builder.commit_public_values();

    let program = builder.compile_program();
    let elapsed = time.elapsed();
    println!("Building took: {:?}", elapsed);
    program
}
