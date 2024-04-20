use p3_baby_bear::{BabyBear, DiffusionMatrixBabybear};
use p3_commit::{ExtensionMmcs, TwoAdicMultiplicativeCoset};
use p3_field::extension::BinomialExtensionField;
use p3_field::{AbstractField, Field, TwoAdicField};
use p3_fri::FriConfig;
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use sp1_core::stark::StarkGenericConfig;
use sp1_recursion_compiler::asm::AsmConfig;
use sp1_recursion_compiler::ir::{Builder, Felt, MemVariable, Var};
use sp1_core::utils::BabyBearPoseidon2;

use crate::fri::types::FriConfigVariable;
use crate::fri::TwoAdicMultiplicativeCosetVariable;

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

pub fn clone<T: MemVariable<C>>(builder: &mut RecursionBuilder, var: &T) -> T {
    let mut arr = builder.dyn_array(1);
    builder.set(&mut arr, 0, var.clone());
    builder.get(&arr, 0)
}

pub fn felt2var(builder: &mut RecursionBuilder, felt: Felt<BabyBear>) -> Var<BabyBear> {
    let bits = builder.num2bits_f(felt);
    builder.bits2num_v(&bits)
}
