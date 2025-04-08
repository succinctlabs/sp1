//! An implementation of Poseidon2 over BN254.

use std::{borrow::Cow, iter::repeat};

use crate::prelude::*;
use itertools::Itertools;
use p3_baby_bear::BabyBear;
use p3_field::{AbstractExtensionField, AbstractField};
use sp1_recursion_core::{
    air::RecursionPublicValues, chips::poseidon2_skinny::WIDTH, D, DIGEST_SIZE, HASH_RATE,
};
use sp1_stark::{
    septic_curve::SepticCurve, septic_digest::SepticDigest, septic_extension::SepticExtension,
};

pub trait CircuitV2Builder<C: Config> {
    fn bits2num_v2_f(
        &mut self,
        bits: impl IntoIterator<Item = Felt<<C as Config>::F>>,
    ) -> Felt<C::F>;
    fn num2bits_v2_f(&mut self, num: Felt<C::F>, num_bits: usize) -> Vec<Felt<C::F>>;
    fn exp_reverse_bits_v2(&mut self, input: Felt<C::F>, power_bits: Vec<Felt<C::F>>)
        -> Felt<C::F>;
    fn batch_fri_v2(
        &mut self,
        alphas: Vec<Ext<C::F, C::EF>>,
        p_at_zs: Vec<Ext<C::F, C::EF>>,
        p_at_xs: Vec<Felt<C::F>>,
    ) -> Ext<C::F, C::EF>;
    fn poseidon2_permute_v2(&mut self, state: [Felt<C::F>; WIDTH]) -> [Felt<C::F>; WIDTH];
    fn poseidon2_hash_v2(&mut self, array: &[Felt<C::F>]) -> [Felt<C::F>; DIGEST_SIZE];
    fn poseidon2_compress_v2(
        &mut self,
        input: impl IntoIterator<Item = Felt<C::F>>,
    ) -> [Felt<C::F>; DIGEST_SIZE];
    fn fri_fold_v2(&mut self, input: CircuitV2FriFoldInput<C>) -> CircuitV2FriFoldOutput<C>;
    fn ext2felt_v2(&mut self, ext: Ext<C::F, C::EF>) -> [Felt<C::F>; D];
    fn add_curve_v2(
        &mut self,
        point1: SepticCurve<Felt<C::F>>,
        point2: SepticCurve<Felt<C::F>>,
    ) -> SepticCurve<Felt<C::F>>;
    fn assert_digest_zero_v2(&mut self, is_real: Felt<C::F>, digest: SepticDigest<Felt<C::F>>);
    fn sum_digest_v2(&mut self, digests: Vec<SepticDigest<Felt<C::F>>>)
        -> SepticDigest<Felt<C::F>>;
    fn select_global_cumulative_sum(
        &mut self,
        is_first_shard: Felt<C::F>,
        vk_digest: SepticDigest<Felt<C::F>>,
    ) -> SepticDigest<Felt<C::F>>;
    fn commit_public_values_v2(&mut self, public_values: RecursionPublicValues<Felt<C::F>>);
    fn cycle_tracker_v2_enter(&mut self, name: impl Into<Cow<'static, str>>);
    fn cycle_tracker_v2_exit(&mut self);
    fn hint_ext_v2(&mut self) -> Ext<C::F, C::EF>;
    fn hint_felt_v2(&mut self) -> Felt<C::F>;
    fn hint_exts_v2(&mut self, len: usize) -> Vec<Ext<C::F, C::EF>>;
    fn hint_felts_v2(&mut self, len: usize) -> Vec<Felt<C::F>>;
}

impl<C: Config<F = BabyBear>> CircuitV2Builder<C> for Builder<C> {
    fn bits2num_v2_f(
        &mut self,
        bits: impl IntoIterator<Item = Felt<<C as Config>::F>>,
    ) -> Felt<<C as Config>::F> {
        let mut num: Felt<_> = self.eval(C::F::zero());
        for (i, bit) in bits.into_iter().enumerate() {
            // Add `bit * 2^i` to the sum.
            num = self.eval(num + bit * C::F::from_wrapped_u32(1 << i));
        }
        num
    }

    /// Converts a felt to bits inside a circuit.
    fn num2bits_v2_f(&mut self, num: Felt<C::F>, num_bits: usize) -> Vec<Felt<C::F>> {
        let output = std::iter::from_fn(|| Some(self.uninit())).take(num_bits).collect::<Vec<_>>();
        self.push_op(DslIr::CircuitV2HintBitsF(output.clone(), num));

        let x: SymbolicFelt<_> = output
            .iter()
            .enumerate()
            .map(|(i, &bit)| {
                self.assert_felt_eq(bit * (bit - C::F::one()), C::F::zero());
                bit * C::F::from_wrapped_u32(1 << i)
            })
            .sum();

        // Range check the bits to be less than the BabyBear modulus.

        assert!(num_bits <= 31, "num_bits must be less than or equal to 31");

        // If there are less than 31 bits, there is nothing to check.
        if num_bits > 30 {
            // Since BabyBear modulus is 2^31 - 2^27 + 1, if any of the top `4` bits are zero, the
            // number is less than 2^27, and we can stop the iteration. Othwriwse, if all the top
            // `4` bits are '1`, we need to check that all the bottom `27` are '0`

            // Get a flag that is zero if any of the top `4` bits are zero, and one otherwise. We
            // can do this by simply taking their product (which is bitwise AND).
            let are_all_top_bits_one: Felt<_> = self.eval(
                output
                    .iter()
                    .rev()
                    .take(4)
                    .copied()
                    .map(SymbolicFelt::from)
                    .product::<SymbolicFelt<_>>(),
            );

            // Assert that if all the top `4` bits are one, then all the bottom `27` bits are zero.
            for bit in output.iter().take(27).copied() {
                self.assert_felt_eq(bit * are_all_top_bits_one, C::F::zero());
            }
        }

        // Check that the original number matches the bit decomposition.
        self.assert_felt_eq(x, num);

        output
    }

    /// A version of `exp_reverse_bits_len` that uses the ExpReverseBitsLen precompile.
    fn exp_reverse_bits_v2(
        &mut self,
        input: Felt<C::F>,
        power_bits: Vec<Felt<C::F>>,
    ) -> Felt<C::F> {
        let output: Felt<_> = self.uninit();
        self.push_op(DslIr::CircuitV2ExpReverseBits(output, input, power_bits));
        output
    }

    /// A version of the `batch_fri` that uses the BatchFRI precompile.
    fn batch_fri_v2(
        &mut self,
        alpha_pows: Vec<Ext<C::F, C::EF>>,
        p_at_zs: Vec<Ext<C::F, C::EF>>,
        p_at_xs: Vec<Felt<C::F>>,
    ) -> Ext<C::F, C::EF> {
        let output: Ext<_, _> = self.uninit();
        self.push_op(DslIr::CircuitV2BatchFRI(Box::new((output, alpha_pows, p_at_zs, p_at_xs))));
        output
    }

    /// Applies the Poseidon2 permutation to the given array.
    fn poseidon2_permute_v2(&mut self, array: [Felt<C::F>; WIDTH]) -> [Felt<C::F>; WIDTH] {
        let output: [Felt<C::F>; WIDTH] = core::array::from_fn(|_| self.uninit());
        self.push_op(DslIr::CircuitV2Poseidon2PermuteBabyBear(Box::new((output, array))));
        output
    }

    /// Applies the Poseidon2 hash function to the given array.
    ///
    /// Reference: [p3_symmetric::PaddingFreeSponge]
    fn poseidon2_hash_v2(&mut self, input: &[Felt<C::F>]) -> [Felt<C::F>; DIGEST_SIZE] {
        // static_assert(RATE < WIDTH)
        let mut state = core::array::from_fn(|_| self.eval(C::F::zero()));
        for input_chunk in input.chunks(HASH_RATE) {
            state[..input_chunk.len()].copy_from_slice(input_chunk);
            state = self.poseidon2_permute_v2(state);
        }
        let state: [Felt<C::F>; DIGEST_SIZE] = state[..DIGEST_SIZE].try_into().unwrap();
        state
    }

    /// Applies the Poseidon2 compression function to the given array.
    ///
    /// Reference: [p3_symmetric::TruncatedPermutation]
    fn poseidon2_compress_v2(
        &mut self,
        input: impl IntoIterator<Item = Felt<C::F>>,
    ) -> [Felt<C::F>; DIGEST_SIZE] {
        // debug_assert!(DIGEST_SIZE * N <= WIDTH);
        let mut pre_iter = input.into_iter().chain(repeat(self.eval(C::F::default())));
        let pre = core::array::from_fn(move |_| pre_iter.next().unwrap());
        let post = self.poseidon2_permute_v2(pre);
        let post: [Felt<C::F>; DIGEST_SIZE] = post[..DIGEST_SIZE].try_into().unwrap();
        post
    }

    /// Runs FRI fold.
    fn fri_fold_v2(&mut self, input: CircuitV2FriFoldInput<C>) -> CircuitV2FriFoldOutput<C> {
        let mut uninit_vec = |len| std::iter::from_fn(|| Some(self.uninit())).take(len).collect();
        let output = CircuitV2FriFoldOutput {
            alpha_pow_output: uninit_vec(input.alpha_pow_input.len()),
            ro_output: uninit_vec(input.ro_input.len()),
        };
        self.push_op(DslIr::CircuitV2FriFold(Box::new((output.clone(), input))));
        output
    }

    /// Decomposes an ext into its felt coordinates.
    fn ext2felt_v2(&mut self, ext: Ext<C::F, C::EF>) -> [Felt<C::F>; D] {
        let felts = core::array::from_fn(|_| self.uninit());
        self.push_op(DslIr::CircuitExt2Felt(felts, ext));
        // Verify that the decomposed extension element is correct.
        let mut reconstructed_ext: Ext<C::F, C::EF> = self.constant(C::EF::zero());
        for i in 0..4 {
            let felt = felts[i];
            let monomial: Ext<C::F, C::EF> = self.constant(C::EF::monomial(i));
            reconstructed_ext = self.eval(reconstructed_ext + monomial * felt);
        }

        self.assert_ext_eq(reconstructed_ext, ext);

        felts
    }

    /// Adds two septic elliptic curve points.
    fn add_curve_v2(
        &mut self,
        point1: SepticCurve<Felt<C::F>>,
        point2: SepticCurve<Felt<C::F>>,
    ) -> SepticCurve<Felt<C::F>> {
        // Hint the curve addition result.
        let point_sum_x: [Felt<C::F>; 7] = core::array::from_fn(|_| self.uninit());
        let point_sum_y: [Felt<C::F>; 7] = core::array::from_fn(|_| self.uninit());
        let point =
            SepticCurve { x: SepticExtension(point_sum_x), y: SepticExtension(point_sum_y) };
        self.push_op(DslIr::CircuitV2HintAddCurve(Box::new((point, point1, point2))));

        // Convert each point into a point over SymbolicFelt.
        let point1_symbolic = SepticCurve::convert(point1, |x| x.into());
        let point2_symbolic = SepticCurve::convert(point2, |x| x.into());
        let point_symbolic = SepticCurve::convert(point, |x| x.into());

        // Evaluate `sum_checker_x` and `sum_checker_y`.
        let sum_checker_x = SepticCurve::<SymbolicFelt<C::F>>::sum_checker_x(
            point1_symbolic,
            point2_symbolic,
            point_symbolic,
        );

        let sum_checker_y = SepticCurve::<SymbolicFelt<C::F>>::sum_checker_y(
            point1_symbolic,
            point2_symbolic,
            point_symbolic,
        );

        // Constrain `sum_checker_x` and `sum_checker_y` to be all zero.
        for limb in sum_checker_x.0 {
            self.assert_felt_eq(limb, C::F::zero());
        }

        for limb in sum_checker_y.0 {
            self.assert_felt_eq(limb, C::F::zero());
        }

        point
    }

    /// Asserts that the `digest` is the zero digest when `is_real` is non-zero.
    fn assert_digest_zero_v2(&mut self, is_real: Felt<C::F>, digest: SepticDigest<Felt<C::F>>) {
        let zero = SepticDigest::<SymbolicFelt<C::F>>::zero();
        for (digest_limb_x, zero_limb_x) in digest.0.x.0.into_iter().zip_eq(zero.0.x.0.into_iter())
        {
            self.assert_felt_eq(is_real * digest_limb_x, is_real * zero_limb_x);
        }
        for (digest_limb_y, zero_limb_y) in digest.0.y.0.into_iter().zip_eq(zero.0.y.0.into_iter())
        {
            self.assert_felt_eq(is_real * digest_limb_y, is_real * zero_limb_y);
        }
    }

    /// Returns the zero digest when `is_first_shard` is zero, and returns the `vk_digest` when
    /// `is_first_shard` is one. It is assumed that `is_first_shard` is already checked to be a
    /// boolean.
    fn select_global_cumulative_sum(
        &mut self,
        is_first_shard: Felt<C::F>,
        vk_digest: SepticDigest<Felt<C::F>>,
    ) -> SepticDigest<Felt<C::F>> {
        let zero = SepticDigest::<SymbolicFelt<C::F>>::zero();
        let one: Felt<C::F> = self.constant(C::F::one());
        let x = SepticExtension(core::array::from_fn(|i| {
            self.eval(is_first_shard * vk_digest.0.x.0[i] + (one - is_first_shard) * zero.0.x.0[i])
        }));
        let y = SepticExtension(core::array::from_fn(|i| {
            self.eval(is_first_shard * vk_digest.0.y.0[i] + (one - is_first_shard) * zero.0.y.0[i])
        }));
        SepticDigest(SepticCurve { x, y })
    }

    // Sums the digests into one.
    fn sum_digest_v2(
        &mut self,
        digests: Vec<SepticDigest<Felt<C::F>>>,
    ) -> SepticDigest<Felt<C::F>> {
        let mut convert_to_felt =
            |point: SepticCurve<C::F>| SepticCurve::convert(point, |value| self.eval(value));

        let start = convert_to_felt(SepticDigest::starting_digest().0);
        let zero_digest = convert_to_felt(SepticDigest::zero().0);

        if digests.is_empty() {
            return SepticDigest(zero_digest);
        }

        let neg_start = convert_to_felt(SepticDigest::starting_digest().0.neg());
        let neg_zero_digest = convert_to_felt(SepticDigest::zero().0.neg());

        let mut ret = start;
        for (i, digest) in digests.clone().into_iter().enumerate() {
            ret = self.add_curve_v2(ret, digest.0);
            if i != digests.len() - 1 {
                ret = self.add_curve_v2(ret, neg_zero_digest)
            }
        }
        SepticDigest(self.add_curve_v2(ret, neg_start))
    }

    // Commits public values.
    fn commit_public_values_v2(&mut self, public_values: RecursionPublicValues<Felt<C::F>>) {
        self.push_op(DslIr::CircuitV2CommitPublicValues(Box::new(public_values)));
    }

    fn cycle_tracker_v2_enter(&mut self, name: impl Into<Cow<'static, str>>) {
        self.push_op(DslIr::CycleTrackerV2Enter(name.into()));
    }

    fn cycle_tracker_v2_exit(&mut self) {
        self.push_op(DslIr::CycleTrackerV2Exit);
    }

    /// Hint a single felt.
    fn hint_felt_v2(&mut self) -> Felt<C::F> {
        self.hint_felts_v2(1)[0]
    }

    /// Hint a single ext.
    fn hint_ext_v2(&mut self) -> Ext<C::F, C::EF> {
        self.hint_exts_v2(1)[0]
    }

    /// Hint a vector of felts.
    fn hint_felts_v2(&mut self, len: usize) -> Vec<Felt<C::F>> {
        let arr = std::iter::from_fn(|| Some(self.uninit())).take(len).collect::<Vec<_>>();
        self.push_op(DslIr::CircuitV2HintFelts(arr[0], len));
        arr
    }

    /// Hint a vector of exts.
    fn hint_exts_v2(&mut self, len: usize) -> Vec<Ext<C::F, C::EF>> {
        let arr = std::iter::from_fn(|| Some(self.uninit())).take(len).collect::<Vec<_>>();
        self.push_op(DslIr::CircuitV2HintExts(arr[0], len));
        arr
    }
}
