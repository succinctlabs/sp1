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
use p3_challenger::CanObserve;
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
use sp1_core::stark::Proof;
use sp1_core::stark::ShardProof;
use sp1_core::stark::VerifyingKey;
use sp1_core::stark::{RiscvAir, StarkGenericConfig};
use sp1_recursion_compiler::asm::AsmConfig;
use sp1_recursion_compiler::asm::VmBuilder;
use sp1_recursion_compiler::ir::Array;
use sp1_recursion_compiler::ir::Builder;
use sp1_recursion_compiler::ir::Felt;
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

// TODO: proof is only necessary now because it's a constant, it should be I/O soon
pub fn build_compress(
    proof: Proof<BabyBearPoseidon2>,
    vk: VerifyingKey<SC>,
) -> (RecursionProgram<Val>, Vec<Vec<Block<Val>>>) {
    let machine = RiscvAir::machine(SC::default());

    let mut challenger_val = machine.config().challenger();
    challenger_val.observe(vk.commit);
    proof.shard_proofs.iter().for_each(|proof| {
        challenger_val.observe(proof.commitment.main_commit);
        challenger_val.observe_slice(&proof.public_values);
    });

    let time = Instant::now();
    let mut builder = VmBuilder::<F, EF>::default();
    let config = const_fri_config(&mut builder, inner_fri_config());
    let pcs = TwoAdicFriPcsVariable { config };

    let mut challenger = DuplexChallengerVariable::new(&mut builder);

    let preprocessed_commit_val: [F; DIGEST_SIZE] = vk.commit.into();
    let preprocessed_commit: Array<C, _> = builder.eval_const(preprocessed_commit_val.to_vec());
    challenger.observe(&mut builder, preprocessed_commit);

    let mut witness_stream = Vec::new();
    let mut shard_proofs = vec![];
    let mut sorted_indices = vec![];
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
        let public_values_felt: Vec<Felt<F>> = proof_val
            .public_values
            .to_vec()
            .iter()
            .map(|x| builder.eval(*x))
            .collect();

        let mut array: Array<C, Felt<F>> = builder.array(public_values_felt.len());
        for (i, x) in public_values_felt.iter().enumerate() {
            builder.set(&mut array, i, *x);
        }

        challenger.observe_slice(&mut builder, array);
        shard_proofs.push(proof);
        sorted_indices.push(sorted_indices_arr);
    }

    for (proof, sorted_indices) in shard_proofs.iter().zip(sorted_indices) {
        StarkVerifier::<C, SC>::verify_shard(
            &mut builder,
            &vk,
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
