use std::thread::current;
use std::time::Instant;

use crate::challenger::CanObserveVariable;
use crate::challenger::DuplexChallengerVariable;
use crate::fri::types::FriConfigVariable;
use crate::fri::TwoAdicFriPcsVariable;
use crate::fri::TwoAdicMultiplicativeCosetVariable;
use crate::hints::Hintable;
use crate::stark::StarkVerifier;
use crate::stark::EMPTY;
use crate::types::ShardCommitmentVariable;
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
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon2::Poseidon2;
use p3_poseidon2::Poseidon2ExternalMatrixGeneral;
use p3_symmetric::PaddingFreeSponge;
use p3_symmetric::TruncatedPermutation;
use sp1_core::air::PublicValues;
use sp1_core::air::Word;
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
pub fn build_compress(
    proof: Proof<BabyBearPoseidon2>,
    sp1_vk: VerifyingKey<SC>,
) -> (RecursionProgram<Val>, Vec<Vec<Block<Val>>>) {
    let machine = RiscvAir::machine(SC::default());

    let mut challenger_val = machine.config().challenger();
    challenger_val.observe(sp1_vk.commit);
    proof.shard_proofs.iter().for_each(|proof| {
        challenger_val.observe(proof.commitment.main_commit);
        let public_values_field = PublicValues::<Word<F>, F>::new(proof.public_values);
        challenger_val.observe_slice(&public_values_field.to_vec());
    });

    let time = Instant::now();
    let mut builder = VmBuilder::<F, EF>::default();
    let config = const_fri_config(&mut builder, inner_fri_config());
    let pcs = TwoAdicFriPcsVariable { config };

    let mut challenger = DuplexChallengerVariable::new(&mut builder);

    let preprocessed_commit_val: [F; DIGEST_SIZE] = sp1_vk.commit.into();
    let preprocessed_commit: Array<C, _> = builder.eval_const(preprocessed_commit_val.to_vec());
    challenger.observe(&mut builder, preprocessed_commit);

    let mut witness_stream = Vec::new();
    let mut shard_proofs = vec![];
    let mut sorted_indices = vec![];

    // Read witness inputs
    let proofs = Vec::<ShardProof<_>>::read(&mut builder);
    let is_recursive_flags = Vec::<usize>::read(&mut builder);
    let chip_indices = Vec::<Vec<usize>>::read(&mut builder);
    let num_proofs = proofs.len();
    let current_challenger = DuplexChallenger::read(&mut builder);
    let mut reconstruct_challenger = DuplexChallenger::read(&mut builder);
    let verify_start_challenger = DuplexChallenger::read(&mut builder);
    let recursion_vk = VerifyingKey::<SC>::read(&mut builder);

    let pre_challenger = clone(&mut builder, &current_challenger);
    let pre_reconstruct_challenger = clone(&mut builder, &reconstruct_challenger);
    let zero: Var<_> = builder.eval_const(F::zero());
    builder
        .range(Usize::Const(0), num_proofs)
        .for_each(|i, builder| {
            let proof = builder.get(&proofs, i);
            builder.if_eq(proof.index, zero).then(|builder| {
                // Ensure that first current_challenger == verify_start_challenger
                DuplexChallengerVariable::assert_eq(
                    current_challenger.clone(),
                    reconstruct_challenger.clone(),
                    builder,
                );

                // Initialize the current challenger
                reconstruct_challenger.assign(reconstruct_challenger.clone(), builder);
                reconstruct_challenger.observe_slice(builder, &recursion_vk.commitment.vec());
            })
            // if i.eq(&zero) {
            //     current
            // } else {
            //     current_challenger.assign(reconstruct_challenger.clone(), &mut builder);
            // }

            // // let is_recursive = usize::read(&mut builder);
            // // let proof = ShardProof::<_>::read(&mut builder);
            // // let sorted_indices_arr = Vec::<usize>::read(&mut builder);
            // // builder
            // //     .range(0, sorted_indices_arr.len())
            // //     .for_each(|i, builder| {
            // //         let el = builder.get(&sorted_indices_arr, i);
            // //         builder.print_v(el);
            // //     });
            // let ShardCommitmentVariable { main_commit, .. } = &proof.commitment;
            // challenger.observe(&mut builder, main_commit.clone());
            // // challenger.observe_slice(&mut builder, &proof.public_values.to_vec());
            // shard_proofs.push(proof);
            // sorted_indices.push(sorted_indices_arr);
        });

    for proof_val in proof.shard_proofs {
        witness_stream.extend(proof_val.write());
        let sorted_indices_raw: Vec<usize> = machine
            .chips_sorted_indices(&proof_val)
            .into_iter()
            .map(|x| match x {
                Some(x) => x,
                None => EMPTY,
            })
            .collect();
        witness_stream.extend(sorted_indices_raw.write());
        let proof = ShardProof::<_>::read(&mut builder);
        let sorted_indices_arr = Vec::<usize>::read(&mut builder);
        builder
            .range(0, sorted_indices_arr.len())
            .for_each(|i, builder| {
                let el = builder.get(&sorted_indices_arr, i);
                builder.print_v(el);
            });
        let ShardCommitmentVariable { main_commit, .. } = &proof.commitment;
        challenger.observe(&mut builder, main_commit.clone());
        let public_values_field = PublicValues::<Word<F>, F>::new(proof_val.public_values);
        let public_values_felt: Vec<Felt<F>> = public_values_field
            .to_vec()
            .iter()
            .map(|x| builder.eval(*x))
            .collect();
        challenger.observe_slice(&mut builder, &public_values_felt);
        shard_proofs.push(proof);
        sorted_indices.push(sorted_indices_arr);
    }

    for (proof, sorted_indices) in shard_proofs.iter().zip(sorted_indices) {
        StarkVerifier::<C, SC>::verify_shard(
            &mut builder,
            &sp1_vk,
            &pcs,
            &machine,
            &mut challenger.clone(),
            proof,
            sorted_indices,
        );
    }

    let program = builder.compile();
    let elapsed = time.elapsed();
    println!("Building took: {:?}", elapsed);
    (program, witness_stream)
}
