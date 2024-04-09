use std::time::Instant;

use crate::challenger::CanObserveVariable;
use crate::challenger::DuplexChallengerVariable;
use crate::fri::types::FriConfigVariable;
use crate::fri::TwoAdicFriPcsVariable;
use crate::fri::TwoAdicMultiplicativeCosetVariable;
use crate::hints::Hintable;
use crate::stark::StarkVerifier;
use p3_baby_bear::BabyBear;
use p3_baby_bear::DiffusionMatrixBabybear;
use p3_challenger::DuplexChallenger;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::ExtensionMmcs;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::extension::BinomialExtensionField;
use p3_field::AbstractField;
use p3_field::Field;
use p3_field::TwoAdicField;
use p3_fri::FriConfig;
use p3_matrix::Dimensions;
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon2::Poseidon2;
use p3_poseidon2::Poseidon2ExternalMatrixGeneral;
use p3_symmetric::PaddingFreeSponge;
use p3_symmetric::TruncatedPermutation;
use sp1_core::air::PublicValues;
use sp1_core::air::Word;
use sp1_core::stark::Dom;
use sp1_core::stark::Proof;
use sp1_core::stark::ShardProof;
use sp1_core::stark::VerifyingKey;
use sp1_core::stark::{RiscvAir, StarkGenericConfig};
use sp1_recursion_compiler::asm::AsmConfig;
use sp1_recursion_compiler::asm::VmBuilder;
use sp1_recursion_compiler::ir::Array;
use sp1_recursion_compiler::ir::Builder;
use sp1_recursion_compiler::ir::Felt;
use sp1_recursion_compiler::ir::MemVariable;
use sp1_recursion_compiler::ir::Usize;
use sp1_recursion_compiler::ir::Var;
use sp1_recursion_compiler::ir::Variable;
use sp1_recursion_core::air::Block;
use sp1_recursion_core::runtime::Program as RecursionProgram;
use sp1_recursion_core::runtime::DIGEST_SIZE;
use sp1_recursion_core::stark::config::inner_fri_config;
use sp1_sdk::utils::BabyBearPoseidon2;

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
        let domain_value: TwoAdicMultiplicativeCosetVariable<_> =
            builder.eval_const(constant_domain);
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

// TODO: proof is only necessary now because it's a constant, it should be I/O soon
pub fn build_reduce(
    sp1_chip_info: Vec<(String, Dom<SC>, Dimensions)>,
    recursion_chip_info: Vec<(String, Dom<SC>, Dimensions)>,
) -> RecursionProgram<Val> {
    let sp1_machine = RiscvAir::machine(SC::default());

    let time = Instant::now();
    let mut builder = VmBuilder::<F, EF>::default();
    let config = const_fri_config(&mut builder, inner_fri_config());
    let pcs = TwoAdicFriPcsVariable { config };

    // let mut challenger = DuplexChallengerVariable::new(&mut builder);

    // let preprocessed_commit_val: [F; DIGEST_SIZE] = sp1_vk.commit.into();
    // let preprocessed_commit: Array<C, _> = builder.eval_const(preprocessed_commit_val.to_vec());
    // challenger.observe(&mut builder, preprocessed_commit);

    // Read witness inputs
    let proofs = Vec::<ShardProof<_>>::read(&mut builder);
    let is_recursive_flags = Vec::<usize>::read(&mut builder);
    let chip_indices = Vec::<Vec<usize>>::read(&mut builder);
    let start_challenger = DuplexChallenger::read(&mut builder);
    let mut reconstruct_challenger = DuplexChallenger::read(&mut builder);
    let sp1_vk = VerifyingKey::<SC>::read(&mut builder);
    let recursion_vk = VerifyingKey::<SC>::read(&mut builder);
    let num_proofs = proofs.len();
    let code = builder.eval_const(F::from_canonical_u32(1));
    builder.print_f(code);

    let pre_start_challenger = clone(&mut builder, &start_challenger);
    let pre_reconstruct_challenger = clone(&mut builder, &reconstruct_challenger);
    let zero: Var<_> = builder.eval_const(F::zero());
    let one: Var<_> = builder.eval_const(F::one());
    let code = builder.eval_const(F::from_canonical_u32(2));
    builder.print_f(code);
    builder
        .range(Usize::Const(0), num_proofs)
        .for_each(|i, builder| {
            let proof = builder.get(&proofs, i);
            let sorted_indices = builder.get(&chip_indices, i);
            let is_recursive = builder.get(&is_recursive_flags, i);
            builder.if_eq(is_recursive, zero).then_or_else(
                // Non-recursive proof
                |builder| {
                    builder.if_eq(proof.index, one).then(|builder| {
                        let code = builder.eval_const(F::from_canonical_u32(3));
                        builder.print_f(code);

                        // Initialize the current challenger
                        // let h: [BabyBear; DIGEST_SIZE] = sp1_vk.commit.into();
                        // let const_commit: DigestVariable<C> = builder.eval_const(h.to_vec());
                        reconstruct_challenger = DuplexChallengerVariable::new(builder);
                        reconstruct_challenger.observe(builder, sp1_vk.commitment.clone());
                        // for j in 0..DIGEST_SIZE {
                        //     let element = builder.get(&sp1_vk.commit, j);
                        //     reconstruct_challenger.observe(builder, element);
                        // }
                        // reconstruct_challenger
                        //     .observe_slice(builder, &recursion_vk.commitment);
                    });
                    for j in 0..DIGEST_SIZE {
                        let element = builder.get(&proof.commitment.main_commit, j);
                        reconstruct_challenger.observe(builder, element);
                        // TODO: observe public values
                        // challenger.observe_slice(&public_values.to_vec());
                    }
                    let code = builder.eval_const(F::from_canonical_u32(4));
                    builder.print_f(code);
                    // reconstruct_challenger
                    //     .observe_slice(builder, &proof.commitment.main_commit.vec());
                    let mut current_challenger = start_challenger.as_clone(builder);
                    StarkVerifier::<C, SC>::verify_shard(
                        builder,
                        &sp1_vk.clone(),
                        &pcs,
                        &sp1_machine,
                        &mut current_challenger,
                        &proof,
                        sorted_indices.clone(),
                        sp1_chip_info.clone(),
                    );
                    let code = builder.eval_const(F::from_canonical_u32(5));
                    builder.print_f(code);
                },
                // Recursive proof
                |builder| {},
            );
        });

    // Public values:
    // (
    //     final current_challenger,
    //     reconstruct_challenger,
    //     pre_challenger,
    //     pre_reconstruct_challenger,
    //     verify_start_challenger,
    //     recursion_vk,
    // )
    // Note we still need to check that verify_start_challenger matches final reconstruct_challenger
    // after observing pv_digest at the end.

    let program = builder.compile();
    let elapsed = time.elapsed();
    println!("Building took: {:?}", elapsed);
    program
}
