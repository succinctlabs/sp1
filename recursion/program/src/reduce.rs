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
use sp1_core::stark::ShardProof;
use sp1_core::stark::VerifyingKey;
use sp1_core::stark::{RiscvAir, StarkGenericConfig};
use sp1_recursion_compiler::asm::AsmConfig;
use sp1_recursion_compiler::asm::VmBuilder;
use sp1_recursion_compiler::ir::Builder;
use sp1_recursion_compiler::ir::Felt;
use sp1_recursion_compiler::ir::MemVariable;
use sp1_recursion_compiler::ir::Usize;
use sp1_recursion_compiler::ir::Var;
use sp1_recursion_core::runtime::Program as RecursionProgram;
use sp1_recursion_core::runtime::DIGEST_SIZE;
use sp1_recursion_core::stark::config::inner_fri_config;
use sp1_recursion_core::stark::RecursionAir;
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

pub fn build_reduce() -> RecursionProgram<Val> {
    let sp1_machine = RiscvAir::machine(SC::default());
    let recursion_machine = RecursionAir::machine(SC::default());

    let time = Instant::now();
    let mut builder = VmBuilder::<F, EF>::default();
    let config = const_fri_config(&mut builder, inner_fri_config());
    let pcs = TwoAdicFriPcsVariable { config };

    // Read witness inputs
    let proofs = Vec::<ShardProof<_>>::read(&mut builder);
    let is_recursive_flags = Vec::<usize>::read(&mut builder);
    let sorted_indices = Vec::<Vec<usize>>::read(&mut builder);
    let sp1_challenger = DuplexChallenger::read(&mut builder);
    let mut reconstruct_challenger = DuplexChallenger::read(&mut builder);
    let recursion_challenger = DuplexChallenger::read(&mut builder);
    let prep_sorted_indices = Vec::<usize>::read(&mut builder);
    let prep_domains = Vec::<TwoAdicMultiplicativeCoset<BabyBear>>::read(&mut builder);
    let recursion_prep_sorted_indices = Vec::<usize>::read(&mut builder);
    let recursion_prep_domains = Vec::<TwoAdicMultiplicativeCoset<BabyBear>>::read(&mut builder);
    let sp1_vk = VerifyingKey::<SC>::read(&mut builder);
    let recursion_vk = VerifyingKey::<SC>::read(&mut builder);
    let num_proofs = proofs.len();

    let _pre_start_challenger = clone(&mut builder, &sp1_challenger);
    let _pre_reconstruct_challenger = clone(&mut builder, &reconstruct_challenger);
    let zero: Var<_> = builder.constant(F::zero());
    let one: Var<_> = builder.constant(F::one());
    let _one_felt: Felt<_> = builder.constant(F::one());
    builder
        .range(Usize::Const(0), num_proofs)
        .for_each(|i, builder| {
            let proof = builder.get(&proofs, i);
            let sorted_indices = builder.get(&sorted_indices, i);
            let is_recursive = builder.get(&is_recursive_flags, i);
            builder.if_eq(is_recursive, zero).then_or_else(
                // Non-recursive proof
                |builder| {
                    let shard_bits = builder.num2bits_f(proof.public_values.shard);
                    let shard = builder.bits2num_v(&shard_bits);
                    builder.if_eq(shard, one).then(|builder| {
                        // Initialize the current challenger
                        reconstruct_challenger = DuplexChallengerVariable::new(builder);
                        reconstruct_challenger.observe(builder, sp1_vk.commitment.clone());
                    });
                    for j in 0..DIGEST_SIZE {
                        let element = builder.get(&proof.commitment.main_commit, j);
                        reconstruct_challenger.observe(builder, element);
                    }
                    // TODO: observe public values
                    // challenger.observe_slice(&public_values.to_vec());
                    let mut current_challenger = sp1_challenger.as_clone(builder);
                    let code = builder.constant(BabyBear::from_canonical_u32(1001));
                    builder.print_v(code);
                    StarkVerifier::<C, SC>::verify_shard(
                        builder,
                        &sp1_vk.clone(),
                        &pcs,
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
                    let mut current_challenger = recursion_challenger.as_clone(builder);
                    for j in 0..DIGEST_SIZE {
                        let element = builder.get(&proof.commitment.main_commit, j);
                        current_challenger.observe(builder, element);
                    }
                    let public_values = proof.public_values.to_vec(builder);
                    current_challenger.observe_slice(builder, &public_values);
                    let code = builder.constant(BabyBear::from_canonical_u32(1099));
                    builder.print_v(code);
                    for j in 0..public_values.len() {
                        let element = builder.get(&proof.public_values.committed_values_digest, j);
                        // current_challenger.observe(builder, element);
                        builder.print_f(element);
                    }
                    StarkVerifier::<C, SC>::verify_shard(
                        builder,
                        &recursion_vk.clone(),
                        &pcs,
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
