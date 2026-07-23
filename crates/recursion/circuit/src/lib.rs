use challenger::{
    CanCopyChallenger, CanObserveVariable, DuplexChallengerVariable, FieldChallengerVariable,
    MultiField32ChallengerVariable,
};
use hash::{FieldHasherVariable, Poseidon2SP1FieldHasherVariable};
use itertools::izip;
use slop_algebra::{AbstractExtensionField, AbstractField, PrimeField32};
use slop_bn254::Bn254Fr;
use slop_challenger::IopCtx;
use slop_koala_bear::{
    KoalaBear_BEGIN_EXT_CONSTS, KoalaBear_END_EXT_CONSTS, KoalaBear_PARTIAL_CONSTS,
};
use sp1_hypercube::operations::poseidon2::{NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS};
use sp1_recursion_compiler::{
    circuit::CircuitV2Builder,
    config::{InnerConfig, OuterConfig},
    ir::{Builder, Config, DslIr, Ext, Felt, SymbolicExt, SymbolicFelt, Var, Variable},
};
use sp1_recursion_executor::{RecursionPublicValues, DIGEST_SIZE, NUM_BITS, PERMUTATION_WIDTH};
use std::iter::{repeat, zip};
use utils::{felt_bytes_to_bn254_var, felts_to_bn254_var, words_to_bytes};

use sp1_hypercube::SP1InnerPcs;
pub mod basefold;
pub mod challenger;
pub mod dummy;
pub mod hash;
pub mod jagged;
pub mod logup_gkr;
pub mod machine;
pub mod shard;
pub mod sumcheck;
mod symbolic;
pub mod utils;
pub mod witness;
pub mod zerocheck;
pub const D: usize = 4;
use sp1_primitives::{SP1ExtensionField, SP1Field, SP1GlobalContext, SP1OuterGlobalContext};

use crate::utils::felt_proof_nonce_to_bn254_var;

pub type Digest<C, SC> = <SC as FieldHasherVariable<C>>::DigestVariable;

pub type InnerSC = SP1InnerPcs;
pub trait SP1FieldConfigVariable<C: CircuitConfig>:
    IopCtx + FieldHasherVariable<C> + Poseidon2SP1FieldHasherVariable<C> + Send + Sync
{
    type FriChallengerVariable: FieldChallengerVariable<C, <C as CircuitConfig>::Bit>
        + CanObserveVariable<C, <Self as FieldHasherVariable<C>>::DigestVariable>
        + CanCopyChallenger<C>;

    /// Get a new challenger corresponding to the given config.
    fn challenger_variable(builder: &mut Builder<C>) -> Self::FriChallengerVariable;

    fn commit_recursion_public_values(
        builder: &mut Builder<C>,
        public_values: RecursionPublicValues<Felt<SP1Field>>,
    );
}

pub trait CircuitConfig: Config {
    type Bit: Copy + Variable<Self>;

    fn read_bit(builder: &mut Builder<Self>) -> Self::Bit;

    fn read_felt(builder: &mut Builder<Self>) -> Felt<SP1Field>;

    fn read_ext(builder: &mut Builder<Self>) -> Ext<SP1Field, SP1ExtensionField>;

    fn assert_bit_zero(builder: &mut Builder<Self>, bit: Self::Bit);

    fn assert_bit_one(builder: &mut Builder<Self>, bit: Self::Bit);

    fn ext2felt(
        builder: &mut Builder<Self>,
        ext: Ext<SP1Field, SP1ExtensionField>,
    ) -> [Felt<SP1Field>; D];

    fn felt2ext(
        builder: &mut Builder<Self>,
        felt: [Felt<SP1Field>; D],
    ) -> Ext<SP1Field, SP1ExtensionField>;

    fn exp_reverse_bits(
        builder: &mut Builder<Self>,
        input: Felt<SP1Field>,
        power_bits: Vec<Self::Bit>,
    ) -> Felt<SP1Field>;

    #[allow(clippy::type_complexity)]
    fn prefix_sum_checks(
        builder: &mut Builder<Self>,
        x1: Vec<Felt<SP1Field>>,
        x2: Vec<Ext<SP1Field, SP1ExtensionField>>,
    ) -> (Ext<SP1Field, SP1ExtensionField>, Felt<SP1Field>);

    fn num2bits(
        builder: &mut Builder<Self>,
        num: Felt<SP1Field>,
        num_bits: usize,
    ) -> Vec<Self::Bit>;

    fn bits2num(
        builder: &mut Builder<Self>,
        bits: impl IntoIterator<Item = Self::Bit>,
    ) -> Felt<SP1Field>;

    #[allow(clippy::type_complexity)]
    fn select_chain_f(
        builder: &mut Builder<Self>,
        should_swap: Self::Bit,
        first: impl IntoIterator<Item = Felt<SP1Field>> + Clone,
        second: impl IntoIterator<Item = Felt<SP1Field>> + Clone,
    ) -> Vec<Felt<SP1Field>>;

    #[allow(clippy::type_complexity)]
    fn select_chain_ef(
        builder: &mut Builder<Self>,
        should_swap: Self::Bit,
        first: impl IntoIterator<Item = Ext<SP1Field, SP1ExtensionField>> + Clone,
        second: impl IntoIterator<Item = Ext<SP1Field, SP1ExtensionField>> + Clone,
    ) -> Vec<Ext<SP1Field, SP1ExtensionField>>;

    fn range_check_felt(builder: &mut Builder<Self>, value: Felt<SP1Field>, num_bits: usize) {
        let bits = Self::num2bits(builder, value, NUM_BITS);
        for bit in bits.into_iter().skip(num_bits) {
            Self::assert_bit_zero(builder, bit);
        }
    }

    fn poseidon2_permute_v2(
        builder: &mut Builder<Self>,
        input: [Felt<SP1Field>; PERMUTATION_WIDTH],
    ) -> [Felt<SP1Field>; PERMUTATION_WIDTH];

    /// Permutes 8 independent states, which must not depend on each other's outputs.
    ///
    /// The default lowers to 8 scalar permutations; configs backed by the recursion VM
    /// override this with a batched operation the executor can run as one SIMD batch.
    fn poseidon2_permute_v2_batch8(
        builder: &mut Builder<Self>,
        states: [[Felt<SP1Field>; PERMUTATION_WIDTH]; 8],
    ) -> [[Felt<SP1Field>; PERMUTATION_WIDTH]; 8] {
        states.map(|state| Self::poseidon2_permute_v2(builder, state))
    }

    fn poseidon2_compress_v2(
        builder: &mut Builder<Self>,
        input: impl IntoIterator<Item = Felt<SP1Field>>,
    ) -> [Felt<SP1Field>; DIGEST_SIZE] {
        let mut pre_iter = input.into_iter().chain(repeat(builder.eval(SP1Field::zero())));
        let pre = core::array::from_fn(move |_| pre_iter.next().unwrap());
        let post = Self::poseidon2_permute_v2(builder, pre);
        let post: [Felt<SP1Field>; DIGEST_SIZE] = post[..DIGEST_SIZE].try_into().unwrap();
        post
    }
}

impl CircuitConfig for InnerConfig {
    type Bit = Felt<SP1Field>;

    fn assert_bit_zero(builder: &mut Builder<Self>, bit: Self::Bit) {
        builder.assert_felt_eq(bit, SP1Field::zero());
    }

    fn assert_bit_one(builder: &mut Builder<Self>, bit: Self::Bit) {
        builder.assert_felt_eq(bit, SP1Field::one());
    }

    fn read_bit(builder: &mut Builder<Self>) -> Self::Bit {
        builder.hint_felt_v2()
    }

    fn read_felt(builder: &mut Builder<Self>) -> Felt<SP1Field> {
        builder.hint_felt_v2()
    }

    fn read_ext(builder: &mut Builder<Self>) -> Ext<SP1Field, SP1ExtensionField> {
        builder.hint_ext_v2()
    }

    fn ext2felt(
        builder: &mut Builder<Self>,
        ext: Ext<SP1Field, SP1ExtensionField>,
    ) -> [Felt<SP1Field>; D] {
        builder.ext2felt_v2(ext)
    }

    fn felt2ext(
        builder: &mut Builder<Self>,
        felt: [Felt<SP1Field>; D],
    ) -> Ext<SP1Field, SP1ExtensionField> {
        let mut reconstructed_ext: Ext<SP1Field, SP1ExtensionField> =
            builder.constant(SP1ExtensionField::zero());
        for i in 0..D {
            let mut monomial_slice = [SP1Field::zero(); D];
            monomial_slice[i] = SP1Field::one();
            let monomial: Ext<SP1Field, SP1ExtensionField> =
                builder.constant(SP1ExtensionField::from_base_slice(&monomial_slice));
            reconstructed_ext = builder.eval(reconstructed_ext + monomial * felt[i]);
        }
        reconstructed_ext
    }

    fn exp_reverse_bits(
        builder: &mut Builder<Self>,
        input: Felt<SP1Field>,
        power_bits: Vec<Felt<SP1Field>>,
    ) -> Felt<SP1Field> {
        let mut result = builder.constant(SP1Field::one());
        let mut power_f = input;
        let bit_len = power_bits.len();

        for i in 1..=bit_len {
            let index = bit_len - i;
            let bit = power_bits[index];
            let prod: Felt<_> = builder.eval(result * power_f);
            result = builder.eval(bit * prod + (SymbolicFelt::one() - bit) * result);
            power_f = builder.eval(power_f * power_f);
        }
        result
    }

    fn prefix_sum_checks(
        builder: &mut Builder<Self>,
        x1: Vec<Felt<SP1Field>>,
        x2: Vec<Ext<SP1Field, SP1ExtensionField>>,
    ) -> (Ext<SP1Field, SP1ExtensionField>, Felt<SP1Field>) {
        builder.prefix_sum_checks_v2(x1, x2)
    }

    fn num2bits(
        builder: &mut Builder<Self>,
        num: Felt<SP1Field>,
        num_bits: usize,
    ) -> Vec<Felt<SP1Field>> {
        builder.num2bits_v2_f(num, num_bits)
    }

    fn bits2num(
        builder: &mut Builder<Self>,
        bits: impl IntoIterator<Item = Felt<SP1Field>>,
    ) -> Felt<SP1Field> {
        builder.bits2num_v2_f(bits)
    }

    fn select_chain_f(
        builder: &mut Builder<Self>,
        should_swap: Self::Bit,
        first: impl IntoIterator<Item = Felt<SP1Field>> + Clone,
        second: impl IntoIterator<Item = Felt<SP1Field>> + Clone,
    ) -> Vec<Felt<SP1Field>> {
        let one: Felt<_> = builder.constant(SP1Field::one());
        let shouldnt_swap: Felt<_> = builder.eval(one - should_swap);

        let id_branch = first.clone().into_iter().chain(second.clone());
        let swap_branch = second.into_iter().chain(first);
        zip(zip(id_branch, swap_branch), zip(repeat(shouldnt_swap), repeat(should_swap)))
            .map(|((id_v, sw_v), (id_c, sw_c))| builder.eval(id_v * id_c + sw_v * sw_c))
            .collect()
    }

    fn select_chain_ef(
        builder: &mut Builder<Self>,
        should_swap: Self::Bit,
        first: impl IntoIterator<Item = Ext<SP1Field, SP1ExtensionField>> + Clone,
        second: impl IntoIterator<Item = Ext<SP1Field, SP1ExtensionField>> + Clone,
    ) -> Vec<Ext<SP1Field, SP1ExtensionField>> {
        let one: Felt<_> = builder.constant(SP1Field::one());
        let shouldnt_swap: Felt<_> = builder.eval(one - should_swap);

        let id_branch = first.clone().into_iter().chain(second.clone());
        let swap_branch = second.into_iter().chain(first);
        zip(zip(id_branch, swap_branch), zip(repeat(shouldnt_swap), repeat(should_swap)))
            .map(|((id_v, sw_v), (id_c, sw_c))| builder.eval(id_v * id_c + sw_v * sw_c))
            .collect()
    }

    fn poseidon2_permute_v2(
        builder: &mut Builder<Self>,
        input: [Felt<SP1Field>; PERMUTATION_WIDTH],
    ) -> [Felt<SP1Field>; PERMUTATION_WIDTH] {
        builder.poseidon2_permute_v2(input)
    }

    fn poseidon2_permute_v2_batch8(
        builder: &mut Builder<Self>,
        states: [[Felt<SP1Field>; PERMUTATION_WIDTH]; 8],
    ) -> [[Felt<SP1Field>; PERMUTATION_WIDTH]; 8] {
        builder.poseidon2_permute_v2_batch8(states)
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WrapConfig;

impl Config for WrapConfig {
    type N = <InnerConfig as Config>::N;
    fn initialize(builder: &mut Builder<Self>) {
        for round in 0..NUM_EXTERNAL_ROUNDS + NUM_INTERNAL_ROUNDS {
            for i in 0..PERMUTATION_WIDTH / D {
                let add_rc = if (NUM_EXTERNAL_ROUNDS / 2
                    ..NUM_EXTERNAL_ROUNDS / 2 + NUM_INTERNAL_ROUNDS)
                    .contains(&round)
                {
                    builder.constant(SP1ExtensionField::from_base({
                        let result = KoalaBear_PARTIAL_CONSTS[round - NUM_EXTERNAL_ROUNDS / 2]
                            .as_canonical_u32();

                        SP1Field::from_wrapped_u32(result)
                    }))
                } else {
                    builder.constant(SP1ExtensionField::from_base_fn(|idx| {
                        let result = if round < NUM_EXTERNAL_ROUNDS / 2 {
                            KoalaBear_BEGIN_EXT_CONSTS[round][i * D + idx].as_canonical_u32()
                        } else {
                            KoalaBear_END_EXT_CONSTS
                                [round - NUM_INTERNAL_ROUNDS - NUM_EXTERNAL_ROUNDS / 2][i * D + idx]
                                .as_canonical_u32()
                        };
                        SP1Field::from_wrapped_u32(result)
                    }))
                };

                builder.poseidon2_constants.push(add_rc);
            }
        }
    }
}

impl CircuitConfig for WrapConfig {
    type Bit = <InnerConfig as CircuitConfig>::Bit;

    fn assert_bit_zero(builder: &mut Builder<Self>, bit: Self::Bit) {
        builder.assert_felt_eq(bit, SP1Field::zero());
    }

    fn assert_bit_one(builder: &mut Builder<Self>, bit: Self::Bit) {
        builder.assert_felt_eq(bit, SP1Field::one());
    }

    fn read_bit(builder: &mut Builder<Self>) -> Self::Bit {
        builder.hint_felt_v2()
    }

    fn read_felt(builder: &mut Builder<Self>) -> Felt<SP1Field> {
        builder.hint_felt_v2()
    }

    fn read_ext(builder: &mut Builder<Self>) -> Ext<SP1Field, SP1ExtensionField> {
        builder.hint_ext_v2()
    }

    fn ext2felt(
        builder: &mut Builder<Self>,
        ext: Ext<SP1Field, SP1ExtensionField>,
    ) -> [Felt<SP1Field>; D] {
        let felts = core::array::from_fn(|_| builder.uninit());
        builder.push_op(DslIr::CircuitChipExt2Felt(felts, ext));
        felts
    }

    fn felt2ext(
        builder: &mut Builder<Self>,
        felt: [Felt<SP1Field>; D],
    ) -> Ext<SP1Field, SP1ExtensionField> {
        let ext = builder.uninit();
        builder.push_op(DslIr::CircuitChipFelt2Ext(ext, felt));
        ext
    }

    fn exp_reverse_bits(
        builder: &mut Builder<Self>,
        input: Felt<SP1Field>,
        power_bits: Vec<Felt<SP1Field>>,
    ) -> Felt<SP1Field> {
        let mut result = builder.constant(SP1Field::one());
        let mut power_f = input;
        let bit_len = power_bits.len();

        for i in 1..=bit_len {
            let index = bit_len - i;
            let bit = power_bits[index];
            let prod: Felt<_> = builder.eval(result * power_f);
            result = builder.eval(bit * prod + (SymbolicFelt::one() - bit) * result);
            power_f = builder.eval(power_f * power_f);
        }
        result
    }

    fn prefix_sum_checks(
        builder: &mut Builder<Self>,
        point_1: Vec<Felt<SP1Field>>,
        point_2: Vec<Ext<SP1Field, SP1ExtensionField>>,
    ) -> (Ext<SP1Field, SP1ExtensionField>, Felt<SP1Field>) {
        let mut acc: Ext<_, _> = builder.uninit();
        builder.push_op(DslIr::ImmE(acc, SP1ExtensionField::one()));
        let mut acc_felt: Felt<_> = builder.uninit();
        builder.push_op(DslIr::ImmF(acc_felt, SP1Field::zero()));
        let one: Felt<_> = builder.constant(SP1Field::one());
        for (i, (x1, x2)) in izip!(point_1.clone(), point_2).enumerate() {
            let prod = builder.uninit();
            builder.push_op(DslIr::MulEF(prod, x2, x1));
            let lagrange_term: Ext<_, _> = builder.eval(SymbolicExt::one() - x1 - x2 + prod + prod);
            // Check that x1 is boolean.
            builder.assert_felt_eq(x1 * (x1 - one), SymbolicFelt::zero());
            acc = builder.eval(acc * lagrange_term);
            // Only need felt of first half of point_1 (current prefix sum).
            if i < point_1.len() / 2 {
                acc_felt = builder.eval(x1 + acc_felt * SymbolicFelt::from_canonical_u32(2));
            }
        }
        (acc, acc_felt)
    }

    fn num2bits(
        builder: &mut Builder<Self>,
        num: Felt<SP1Field>,
        num_bits: usize,
    ) -> Vec<Felt<SP1Field>> {
        builder.num2bits_v2_f(num, num_bits)
    }

    fn bits2num(
        builder: &mut Builder<Self>,
        bits: impl IntoIterator<Item = Felt<SP1Field>>,
    ) -> Felt<SP1Field> {
        builder.bits2num_v2_f(bits)
    }

    fn select_chain_f(
        builder: &mut Builder<Self>,
        should_swap: Self::Bit,
        first: impl IntoIterator<Item = Felt<SP1Field>> + Clone,
        second: impl IntoIterator<Item = Felt<SP1Field>> + Clone,
    ) -> Vec<Felt<SP1Field>> {
        let one: Felt<_> = builder.constant(SP1Field::one());
        let shouldnt_swap: Felt<_> = builder.eval(one - should_swap);

        let id_branch = first.clone().into_iter().chain(second.clone());
        let swap_branch = second.into_iter().chain(first);
        zip(zip(id_branch, swap_branch), zip(repeat(shouldnt_swap), repeat(should_swap)))
            .map(|((id_v, sw_v), (id_c, sw_c))| builder.eval(id_v * id_c + sw_v * sw_c))
            .collect()
    }

    fn select_chain_ef(
        builder: &mut Builder<Self>,
        should_swap: Self::Bit,
        first: impl IntoIterator<Item = Ext<SP1Field, SP1ExtensionField>> + Clone,
        second: impl IntoIterator<Item = Ext<SP1Field, SP1ExtensionField>> + Clone,
    ) -> Vec<Ext<SP1Field, SP1ExtensionField>> {
        let one: Felt<_> = builder.constant(SP1Field::one());
        let shouldnt_swap: Felt<_> = builder.eval(one - should_swap);

        let id_branch = first.clone().into_iter().chain(second.clone());
        let swap_branch = second.into_iter().chain(first);
        zip(zip(id_branch, swap_branch), zip(repeat(shouldnt_swap), repeat(should_swap)))
            .map(|((id_v, sw_v), (id_c, sw_c))| builder.eval(id_v * id_c + sw_v * sw_c))
            .collect()
    }

    fn poseidon2_permute_v2(
        builder: &mut Builder<Self>,
        input: [Felt<SP1Field>; PERMUTATION_WIDTH],
    ) -> [Felt<SP1Field>; PERMUTATION_WIDTH] {
        let mut state = Self::blockify(builder, input);
        for i in 0..NUM_EXTERNAL_ROUNDS / 2 {
            state = Self::external_round(builder, state, i);
        }
        for i in 0..NUM_INTERNAL_ROUNDS {
            state[0] = Self::internal_constant_addition(builder, state[0], i);
            state[0] = Self::pow7_internal(builder, state[0]);
            state = Self::internal_linear_layer(builder, state);
        }
        for i in NUM_EXTERNAL_ROUNDS / 2..NUM_EXTERNAL_ROUNDS {
            state = Self::external_round(builder, state, i);
        }
        Self::unblockify(builder, state)
    }
}

impl WrapConfig {
    fn blockify(
        builder: &mut Builder<Self>,
        input: [Felt<SP1Field>; PERMUTATION_WIDTH],
    ) -> [Ext<SP1Field, SP1ExtensionField>; PERMUTATION_WIDTH / D] {
        let mut ret: [Ext<SP1Field, SP1ExtensionField>; PERMUTATION_WIDTH / D] =
            core::array::from_fn(|_| builder.uninit());
        for i in 0..PERMUTATION_WIDTH / D {
            ret[i] = Self::felt2ext(builder, input[i * D..i * D + D].try_into().unwrap());
        }
        ret
    }

    fn unblockify(
        builder: &mut Builder<Self>,
        input: [Ext<SP1Field, SP1ExtensionField>; PERMUTATION_WIDTH / D],
    ) -> [Felt<SP1Field>; PERMUTATION_WIDTH] {
        let mut ret = core::array::from_fn(|_| builder.uninit());
        for i in 0..PERMUTATION_WIDTH / D {
            let felts = Self::ext2felt(builder, input[i]);
            for j in 0..D {
                ret[i * D + j] = felts[j];
            }
        }
        ret
    }

    fn external_round(
        builder: &mut Builder<Self>,
        input: [Ext<SP1Field, SP1ExtensionField>; PERMUTATION_WIDTH / D],
        round_index: usize,
    ) -> [Ext<SP1Field, SP1ExtensionField>; PERMUTATION_WIDTH / D] {
        let mut state = input;
        if round_index == 0 {
            state = Self::external_linear_layer(builder, state);
        }
        state = Self::external_constant_addition(builder, state, round_index);
        #[allow(clippy::needless_range_loop)]
        for i in 0..PERMUTATION_WIDTH / D {
            state[i] = Self::pow7(builder, state[i]);
        }
        state = Self::external_linear_layer(builder, state);
        state
    }

    fn external_linear_layer(
        builder: &mut Builder<Self>,
        input: [Ext<SP1Field, SP1ExtensionField>; PERMUTATION_WIDTH / D],
    ) -> [Ext<SP1Field, SP1ExtensionField>; PERMUTATION_WIDTH / D] {
        let output = core::array::from_fn(|_| builder.uninit());
        builder.push_op(DslIr::Poseidon2ExternalLinearLayer(Box::new((output, input))));
        output
    }

    fn internal_linear_layer(
        builder: &mut Builder<Self>,
        input: [Ext<SP1Field, SP1ExtensionField>; PERMUTATION_WIDTH / D],
    ) -> [Ext<SP1Field, SP1ExtensionField>; PERMUTATION_WIDTH / D] {
        let output = core::array::from_fn(|_| builder.uninit());
        builder.push_op(DslIr::Poseidon2InternalLinearLayer(Box::new((output, input))));
        output
    }

    fn pow7(
        builder: &mut Builder<Self>,
        input: Ext<SP1Field, SP1ExtensionField>,
    ) -> Ext<SP1Field, SP1ExtensionField> {
        let output = builder.uninit();
        builder.push_op(DslIr::Poseidon2ExternalSBOX(output, input));
        output
    }

    fn pow7_internal(
        builder: &mut Builder<Self>,
        input: Ext<SP1Field, SP1ExtensionField>,
    ) -> Ext<SP1Field, SP1ExtensionField> {
        let output = builder.uninit();
        builder.push_op(DslIr::Poseidon2InternalSBOX(output, input));
        output
    }

    fn external_constant_addition(
        builder: &mut Builder<Self>,
        input: [Ext<SP1Field, SP1ExtensionField>; PERMUTATION_WIDTH / D],
        round_index: usize,
    ) -> [Ext<SP1Field, SP1ExtensionField>; PERMUTATION_WIDTH / D] {
        let output = core::array::from_fn(|_| builder.uninit());
        let round = if round_index < NUM_EXTERNAL_ROUNDS / 2 {
            round_index
        } else {
            round_index + NUM_INTERNAL_ROUNDS
        };
        for i in 0..PERMUTATION_WIDTH / D {
            let add_rc = builder.poseidon2_constants[(PERMUTATION_WIDTH / D) * round + i];
            builder.push_op(DslIr::AddE(output[i], input[i], add_rc));
        }

        output
    }

    fn internal_constant_addition(
        builder: &mut Builder<Self>,
        input: Ext<SP1Field, SP1ExtensionField>,
        round_index: usize,
    ) -> Ext<SP1Field, SP1ExtensionField> {
        let round = round_index + NUM_EXTERNAL_ROUNDS / 2;
        let add_rc = builder.poseidon2_constants[(PERMUTATION_WIDTH / D) * round];
        let output = builder.uninit();
        builder.push_op(DslIr::AddE(output, input, add_rc));
        output
    }
}

impl CircuitConfig for OuterConfig {
    type Bit = Var<<Self as Config>::N>;

    fn assert_bit_zero(builder: &mut Builder<Self>, bit: Self::Bit) {
        builder.assert_var_eq(bit, Self::N::zero());
    }

    fn assert_bit_one(builder: &mut Builder<Self>, bit: Self::Bit) {
        builder.assert_var_eq(bit, Self::N::one());
    }

    fn read_bit(builder: &mut Builder<Self>) -> Self::Bit {
        builder.witness_var()
    }

    fn read_felt(builder: &mut Builder<Self>) -> Felt<SP1Field> {
        builder.witness_felt()
    }

    fn read_ext(builder: &mut Builder<Self>) -> Ext<SP1Field, SP1ExtensionField> {
        builder.witness_ext()
    }

    fn ext2felt(
        builder: &mut Builder<Self>,
        ext: Ext<SP1Field, SP1ExtensionField>,
    ) -> [Felt<SP1Field>; D] {
        let felts = core::array::from_fn(|_| builder.uninit());
        builder.push_op(DslIr::CircuitExt2Felt(felts, ext));
        felts
    }

    fn felt2ext(
        builder: &mut Builder<Self>,
        felt: [Felt<SP1Field>; D],
    ) -> Ext<SP1Field, SP1ExtensionField> {
        let ext = builder.uninit();
        builder.push_op(DslIr::CircuitFelts2Ext(felt, ext));
        ext
    }

    fn exp_reverse_bits(
        builder: &mut Builder<Self>,
        input: Felt<SP1Field>,
        power_bits: Vec<Var<<Self as Config>::N>>,
    ) -> Felt<SP1Field> {
        let mut result = builder.constant(SP1Field::one());
        let power_f = input;
        let bit_len = power_bits.len();

        for i in 1..=bit_len {
            let index = bit_len - i;
            let bit = power_bits[index];
            let prod = builder.eval(result * power_f);
            result = builder.select_f(bit, prod, result);
            builder.assign(power_f, power_f * power_f);
        }
        result
    }

    fn prefix_sum_checks(
        builder: &mut Builder<Self>,
        point_1: Vec<Felt<SP1Field>>,
        point_2: Vec<Ext<SP1Field, SP1ExtensionField>>,
    ) -> (Ext<SP1Field, SP1ExtensionField>, Felt<SP1Field>) {
        let acc: Ext<_, _> = builder.uninit();
        builder.push_op(DslIr::ImmE(acc, SP1ExtensionField::one()));
        let mut acc_felt: Felt<_> = builder.uninit();
        builder.push_op(DslIr::ImmF(acc_felt, SP1Field::zero()));
        for (i, (x1, x2)) in izip!(point_1.clone(), point_2).enumerate() {
            builder.push_op(DslIr::EqEval(x1, x2, acc));
            // Only need felt of first half of point_1 (current prefix sum).
            if i < point_1.len() / 2 {
                acc_felt = builder.eval(x1 + acc_felt * SymbolicFelt::from_canonical_u32(2));
            }
        }
        (acc, acc_felt)
    }

    fn num2bits(
        builder: &mut Builder<Self>,
        num: Felt<SP1Field>,
        num_bits: usize,
    ) -> Vec<Var<<Self as Config>::N>> {
        builder.num2bits_f_circuit(num)[..num_bits].to_vec()
    }

    fn bits2num(
        builder: &mut Builder<Self>,
        bits: impl IntoIterator<Item = Var<<Self as Config>::N>>,
    ) -> Felt<SP1Field> {
        let result = builder.eval(SP1Field::zero());
        for (i, bit) in bits.into_iter().enumerate() {
            let to_add: Felt<_> = builder.uninit();
            let pow2 = builder.constant(SP1Field::from_canonical_u32(1 << i));
            let zero = builder.constant(SP1Field::zero());
            builder.push_op(DslIr::CircuitSelectF(bit, pow2, zero, to_add));
            builder.assign(result, result + to_add);
        }
        result
    }

    fn select_chain_f(
        builder: &mut Builder<Self>,
        should_swap: Self::Bit,
        first: impl IntoIterator<Item = Felt<SP1Field>> + Clone,
        second: impl IntoIterator<Item = Felt<SP1Field>> + Clone,
    ) -> Vec<Felt<SP1Field>> {
        let id_branch = first.clone().into_iter().chain(second.clone());
        let swap_branch = second.into_iter().chain(first);
        zip(id_branch, swap_branch)
            .map(|(id_v, sw_v): (Felt<_>, Felt<_>)| -> Felt<_> {
                let result: Felt<_> = builder.uninit();
                builder.push_op(DslIr::CircuitSelectF(should_swap, sw_v, id_v, result));
                result
            })
            .collect()
    }

    fn select_chain_ef(
        builder: &mut Builder<Self>,
        should_swap: Self::Bit,
        first: impl IntoIterator<Item = Ext<SP1Field, SP1ExtensionField>> + Clone,
        second: impl IntoIterator<Item = Ext<SP1Field, SP1ExtensionField>> + Clone,
    ) -> Vec<Ext<SP1Field, SP1ExtensionField>> {
        let id_branch = first.clone().into_iter().chain(second.clone());
        let swap_branch = second.into_iter().chain(first);
        zip(id_branch, swap_branch)
            .map(|(id_v, sw_v): (Ext<_, _>, Ext<_, _>)| -> Ext<_, _> {
                let result: Ext<_, _> = builder.uninit();
                builder.push_op(DslIr::CircuitSelectE(should_swap, sw_v, id_v, result));
                result
            })
            .collect()
    }

    fn poseidon2_permute_v2(
        _: &mut Builder<Self>,
        _: [Felt<SP1Field>; PERMUTATION_WIDTH],
    ) -> [Felt<SP1Field>; PERMUTATION_WIDTH] {
        unimplemented!();
    }
}

impl<C: CircuitConfig<Bit = Felt<SP1Field>>> SP1FieldConfigVariable<C> for SP1GlobalContext {
    type FriChallengerVariable = DuplexChallengerVariable<C>;

    fn challenger_variable(builder: &mut Builder<C>) -> Self::FriChallengerVariable {
        DuplexChallengerVariable::new(builder)
    }

    fn commit_recursion_public_values(
        builder: &mut Builder<C>,
        public_values: RecursionPublicValues<Felt<SP1Field>>,
    ) {
        builder.commit_public_values_v2(public_values);
    }
}

impl<C: CircuitConfig<N = Bn254Fr, Bit = Var<Bn254Fr>>> SP1FieldConfigVariable<C>
    for SP1OuterGlobalContext
{
    type FriChallengerVariable = MultiField32ChallengerVariable<C>;

    fn challenger_variable(builder: &mut Builder<C>) -> Self::FriChallengerVariable {
        MultiField32ChallengerVariable::new(builder)
    }

    fn commit_recursion_public_values(
        builder: &mut Builder<C>,
        public_values: RecursionPublicValues<Felt<SP1Field>>,
    ) {
        let committed_values_digest_bytes_felts: [Felt<_>; 32] =
            words_to_bytes(&public_values.committed_value_digest).try_into().unwrap();
        let committed_values_digest_bytes: Var<_> =
            felt_bytes_to_bn254_var(builder, &committed_values_digest_bytes_felts);
        builder.commit_committed_values_digest_circuit(committed_values_digest_bytes);

        let vkey_hash = felts_to_bn254_var(builder, &public_values.sp1_vk_digest);
        builder.commit_vkey_hash_circuit(vkey_hash);

        let exit_code = public_values.exit_code;
        let var_exit_code: Var<C::N> = builder.felt2var_circuit(exit_code);
        builder.commit_exit_code_circuit(var_exit_code);

        let vk_root: Var<_> = felts_to_bn254_var(builder, &public_values.vk_root);
        builder.commit_vk_root_circuit(vk_root);

        let proof_nonce: Var<_> =
            felt_proof_nonce_to_bn254_var(builder, &public_values.proof_nonce);
        builder.commit_proof_nonce_circuit(proof_nonce);
    }
}
