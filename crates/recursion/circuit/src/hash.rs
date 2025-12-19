use std::{
    fmt::Debug,
    iter::{repeat, zip},
};

use itertools::Itertools;
use p3_baby_bear::BabyBear;
use p3_field::{AbstractField, Field};

use p3_bls12_377_fr::Bls12377Fr;
use p3_symmetric::Permutation;
use sp1_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Config, DslIr, Felt, Var},
};
use sp1_recursion_core::{
    stark::{outer_perm, BabyBearPoseidon2Outer, OUTER_MULTI_FIELD_CHALLENGER_WIDTH},
    DIGEST_SIZE, HASH_RATE, PERMUTATION_WIDTH,
};
use sp1_stark::{baby_bear_poseidon2::BabyBearPoseidon2, inner_perm};

use crate::{
    challenger::{reduce_32, POSEIDON_2_BB_RATE},
    CircuitConfig,
};

pub trait FieldHasher<F: Field> {
    type Digest: Copy + Default + Eq + Ord + Copy + Debug + Send + Sync;

    fn constant_compress(input: [Self::Digest; 2]) -> Self::Digest;
}

pub trait Posedion2BabyBearHasherVariable<C: CircuitConfig> {
    fn poseidon2_permute(
        builder: &mut Builder<C>,
        state: [Felt<C::F>; PERMUTATION_WIDTH],
    ) -> [Felt<C::F>; PERMUTATION_WIDTH];

    /// Applies the Poseidon2 hash function to the given array.
    ///
    /// Reference: [p3_symmetric::PaddingFreeSponge]
    fn poseidon2_hash(builder: &mut Builder<C>, input: &[Felt<C::F>]) -> [Felt<C::F>; DIGEST_SIZE] {
        // static_assert(RATE < WIDTH)
        let mut state = core::array::from_fn(|_| builder.eval(C::F::zero()));
        for input_chunk in input.chunks(HASH_RATE) {
            state[..input_chunk.len()].copy_from_slice(input_chunk);
            state = Self::poseidon2_permute(builder, state);
        }
        let digest: [Felt<C::F>; DIGEST_SIZE] = state[..DIGEST_SIZE].try_into().unwrap();
        digest
    }
}

pub trait FieldHasherVariable<C: CircuitConfig>: FieldHasher<C::F> {
    type DigestVariable: Clone + Copy;

    fn hash(builder: &mut Builder<C>, input: &[Felt<C::F>]) -> Self::DigestVariable;

    fn compress(builder: &mut Builder<C>, input: [Self::DigestVariable; 2])
        -> Self::DigestVariable;

    fn assert_digest_eq(builder: &mut Builder<C>, a: Self::DigestVariable, b: Self::DigestVariable);

    // Encountered many issues trying to make the following two parametrically polymorphic.
    fn select_chain_digest(
        builder: &mut Builder<C>,
        should_swap: C::Bit,
        input: [Self::DigestVariable; 2],
    ) -> [Self::DigestVariable; 2];

    fn print_digest(builder: &mut Builder<C>, digest: Self::DigestVariable);
}

impl FieldHasher<BabyBear> for BabyBearPoseidon2 {
    type Digest = [BabyBear; DIGEST_SIZE];

    fn constant_compress(input: [Self::Digest; 2]) -> Self::Digest {
        let mut pre_iter = input.into_iter().flatten().chain(repeat(BabyBear::zero()));
        let mut pre = core::array::from_fn(move |_| pre_iter.next().unwrap());
        (inner_perm()).permute_mut(&mut pre);
        pre[..DIGEST_SIZE].try_into().unwrap()
    }
}

impl<C: CircuitConfig<F = BabyBear>> Posedion2BabyBearHasherVariable<C> for BabyBearPoseidon2 {
    fn poseidon2_permute(
        builder: &mut Builder<C>,
        input: [Felt<<C>::F>; PERMUTATION_WIDTH],
    ) -> [Felt<<C>::F>; PERMUTATION_WIDTH] {
        builder.poseidon2_permute_v2(input)
    }
}

impl<C: CircuitConfig> Posedion2BabyBearHasherVariable<C> for BabyBearPoseidon2Outer {
    fn poseidon2_permute(
        builder: &mut Builder<C>,
        state: [Felt<<C>::F>; PERMUTATION_WIDTH],
    ) -> [Felt<<C>::F>; PERMUTATION_WIDTH] {
        let state: [Felt<_>; PERMUTATION_WIDTH] = state.map(|x| builder.eval(x));
        builder.push_op(DslIr::CircuitPoseidon2PermuteBabyBear(Box::new(state)));
        state
    }
}

impl<C: CircuitConfig<F = BabyBear, Bit = Felt<BabyBear>>> FieldHasherVariable<C>
    for BabyBearPoseidon2
{
    type DigestVariable = [Felt<BabyBear>; DIGEST_SIZE];

    fn hash(builder: &mut Builder<C>, input: &[Felt<<C as Config>::F>]) -> Self::DigestVariable {
        <Self as Posedion2BabyBearHasherVariable<C>>::poseidon2_hash(builder, input)
    }

    fn compress(
        builder: &mut Builder<C>,
        input: [Self::DigestVariable; 2],
    ) -> Self::DigestVariable {
        builder.poseidon2_compress_v2(input.into_iter().flatten())
    }

    fn assert_digest_eq(
        builder: &mut Builder<C>,
        a: Self::DigestVariable,
        b: Self::DigestVariable,
    ) {
        // Push the instruction directly instead of passing through `assert_felt_eq` in order to
        //avoid symbolic expression overhead.
        zip(a, b).for_each(|(e1, e2)| builder.push_op(DslIr::AssertEqF(e1, e2)));
    }

    fn select_chain_digest(
        builder: &mut Builder<C>,
        should_swap: <C as CircuitConfig>::Bit,
        input: [Self::DigestVariable; 2],
    ) -> [Self::DigestVariable; 2] {
        let result0: [Felt<BabyBear>; DIGEST_SIZE] = core::array::from_fn(|_| builder.uninit());
        let result1: [Felt<BabyBear>; DIGEST_SIZE] = core::array::from_fn(|_| builder.uninit());

        (0..DIGEST_SIZE).for_each(|i| {
            builder.push_op(DslIr::Select(
                should_swap,
                result0[i],
                result1[i],
                input[0][i],
                input[1][i],
            ));
        });

        [result0, result1]
    }

    fn print_digest(builder: &mut Builder<C>, digest: Self::DigestVariable) {
        for d in digest.iter() {
            builder.print_f(*d);
        }
    }
}

pub const BN254_DIGEST_SIZE: usize = 1;

impl FieldHasher<BabyBear> for BabyBearPoseidon2Outer {
    type Digest = [Bls12377Fr; BN254_DIGEST_SIZE];

    fn constant_compress(input: [Self::Digest; 2]) -> Self::Digest {
        let mut state = [input[0][0], input[1][0], Bls12377Fr::zero()];
        outer_perm().permute_mut(&mut state);
        [state[0]; BN254_DIGEST_SIZE]
    }
}

impl<C: CircuitConfig<F = BabyBear, N = Bls12377Fr, Bit = Var<Bls12377Fr>>> FieldHasherVariable<C>
    for BabyBearPoseidon2Outer
{
    type DigestVariable = [Var<Bls12377Fr>; BN254_DIGEST_SIZE];

    fn hash(builder: &mut Builder<C>, input: &[Felt<<C as Config>::F>]) -> Self::DigestVariable {
        assert!(C::N::bits() == p3_bls12_377_fr::Bls12377Fr::bits());
        assert!(C::F::bits() == p3_baby_bear::BabyBear::bits());
        let num_f_elms = C::N::bits() / C::F::bits();
        let mut state: [Var<C::N>; OUTER_MULTI_FIELD_CHALLENGER_WIDTH] =
            [builder.eval(C::N::zero()), builder.eval(C::N::zero()), builder.eval(C::N::zero())];
        for block_chunk in &input.iter().chunks(POSEIDON_2_BB_RATE) {
            for (chunk_id, chunk) in (&block_chunk.chunks(num_f_elms)).into_iter().enumerate() {
                let chunk = chunk.copied().collect::<Vec<_>>();
                state[chunk_id] = reduce_32(builder, chunk.as_slice());
            }
            builder.push_op(DslIr::CircuitPoseidon2Permute(state))
        }

        [state[0]; BN254_DIGEST_SIZE]
    }

    fn compress(
        builder: &mut Builder<C>,
        input: [Self::DigestVariable; 2],
    ) -> Self::DigestVariable {
        let state: [Var<C::N>; OUTER_MULTI_FIELD_CHALLENGER_WIDTH] =
            [builder.eval(input[0][0]), builder.eval(input[1][0]), builder.eval(C::N::zero())];
        builder.push_op(DslIr::CircuitPoseidon2Permute(state));
        [state[0]; BN254_DIGEST_SIZE]
    }

    fn assert_digest_eq(
        builder: &mut Builder<C>,
        a: Self::DigestVariable,
        b: Self::DigestVariable,
    ) {
        zip(a, b).for_each(|(e1, e2)| builder.assert_var_eq(e1, e2));
    }

    fn select_chain_digest(
        builder: &mut Builder<C>,
        should_swap: <C as CircuitConfig>::Bit,
        input: [Self::DigestVariable; 2],
    ) -> [Self::DigestVariable; 2] {
        let result0: [Var<_>; BN254_DIGEST_SIZE] = core::array::from_fn(|j| {
            let result = builder.uninit();
            builder.push_op(DslIr::CircuitSelectV(should_swap, input[1][j], input[0][j], result));
            result
        });
        let result1: [Var<_>; BN254_DIGEST_SIZE] = core::array::from_fn(|j| {
            let result = builder.uninit();
            builder.push_op(DslIr::CircuitSelectV(should_swap, input[0][j], input[1][j], result));
            result
        });

        [result0, result1]
    }

    fn print_digest(builder: &mut Builder<C>, digest: Self::DigestVariable) {
        for d in digest.iter() {
            builder.print_v(*d);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::{BigInt, BigUint, Sign};
    use num_traits::{One, Signed, ToPrimitive, Zero};

    /// Offline check (inspired by `audits/rkm0959.md` §3-1) that the base-2^32 packing used by
    /// `reduce_32` is injective modulo the Fr377 scalar field, under the limb bounds we use in
    /// practice (BabyBear elements).
    ///
    /// Concretely, for BabyBear modulus p = 2013265921 (< 2^31), we assert there is no non-trivial
    /// solution to:
    ///
    ///     sum_{i=0..7} z_i * 2^(32i) = k * q
    ///
    /// where q = Fr377 modulus and each z_i ∈ [-(p-1), (p-1)].
    #[test]
    fn test_reduce_32_packing_injective_mod_fr377_under_babybear_bounds() {
        // BabyBear prime modulus.
        let p_bb = BigInt::from(2013265921u64);
        let z_bound = &p_bb - BigInt::one(); // max |z_i|

        // Fr377 prime modulus (q).
        let q: BigUint = Bls12377Fr::order();
        let q = BigInt::from_biguint(Sign::Plus, q);

        // Conservative bound: |Z| < 2^256, so |k| <= floor(2^256 / q) + 1.
        let two_256 = BigUint::one() << 256;
        let max_k_u = (two_256 / q.magnitude()) + BigUint::from(2u32);
        let max_k = max_k_u
            .to_i64()
            .expect("unexpectedly large max_k; assumption violated");

        // Base B = 2^31 for limb extraction and centered reduction (matches `reduce_32`).
        let base = BigInt::one() << 31;
        let half = BigInt::one() << 30;

        // Helper: Euclidean mod in [0, base).
        let mod_euclid = |x: &BigInt| -> BigInt {
            let mut r = x % &base;
            if r.is_negative() {
                r += &base;
            }
            r
        };

        // Try each candidate multiple k. For each k, reconstruct the unique possible z_i sequence
        // (if any) consistent with base-2^32 expansion and our bounds, and reject if any non-zero
        // solution exists.
        for k in -max_k..=max_k {
            let mut t = &q * BigInt::from(k);
            let mut zs: [BigInt; 8] = core::array::from_fn(|_| BigInt::zero());
            let mut ok = true;

            for i in 0..8 {
                // z_i ≡ t (mod 2^32)
                let mut r = mod_euclid(&t); // 0..2^32-1
                // center-lift to (-2^31, 2^31]
                if r >= half {
                    r -= &base;
                }

                // Enforce z_i ∈ [-(p-1), (p-1)].
                if r.signed_abs() > z_bound {
                    ok = false;
                    break;
                }

                // Peel off the limb.
                t = (t - &r) / &base;
                zs[i] = r;
            }

            if !ok {
                continue;
            }
            if !t.is_zero() {
                continue;
            }

            // We found a valid reconstruction; ensure it's the trivial one (k=0, all z_i=0).
            let non_trivial = k != 0 || zs.iter().any(|z| !z.is_zero());
            assert!(
                !non_trivial,
                "Found non-trivial collision: k={k}, z={zs:?}"
            );
        }
    }
}
