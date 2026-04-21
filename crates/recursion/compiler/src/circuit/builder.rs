//! An implementation of Poseidon2 over BN254.

use std::borrow::Cow;

use crate::prelude::*;
use itertools::Itertools;
use slop_algebra::{AbstractExtensionField, AbstractField};
use sp1_hypercube::{
    septic_curve::SepticCurve, septic_digest::SepticDigest, septic_extension::SepticExtension,
};
use sp1_primitives::{SP1ExtensionField, SP1Field};
use sp1_recursion_executor::{RecursionPublicValues, D, PERMUTATION_WIDTH};

pub trait CircuitV2Builder<C: Config> {
    fn bits2num_v2_f(&mut self, bits: impl IntoIterator<Item = Felt<SP1Field>>) -> Felt<SP1Field>;
    fn num2bits_v2_f(&mut self, num: Felt<SP1Field>, num_bits: usize) -> Vec<Felt<SP1Field>>;
    fn prefix_sum_checks_v2(
        &mut self,
        point_1: Vec<Felt<SP1Field>>,
        point_2: Vec<Ext<SP1Field, SP1ExtensionField>>,
    ) -> (Ext<SP1Field, SP1ExtensionField>, Felt<SP1Field>);
    fn poseidon2_permute_v2(
        &mut self,
        state: [Felt<SP1Field>; PERMUTATION_WIDTH],
    ) -> [Felt<SP1Field>; PERMUTATION_WIDTH];
    fn ext2felt_v2(&mut self, ext: Ext<SP1Field, SP1ExtensionField>) -> [Felt<SP1Field>; D];
    fn add_curve_v2(
        &mut self,
        point1: SepticCurve<Felt<SP1Field>>,
        point2: SepticCurve<Felt<SP1Field>>,
    ) -> SepticCurve<Felt<SP1Field>>;
    fn assert_digest_zero_v2(
        &mut self,
        is_real: Felt<SP1Field>,
        digest: SepticDigest<Felt<SP1Field>>,
    );
    fn sum_digest_v2(
        &mut self,
        digests: Vec<SepticDigest<Felt<SP1Field>>>,
    ) -> SepticDigest<Felt<SP1Field>>;
    fn select_global_cumulative_sum(
        &mut self,
        is_first_execution_shard: Felt<SP1Field>,
        vk_digest: SepticDigest<Felt<SP1Field>>,
    ) -> SepticDigest<Felt<SP1Field>>;
    fn commit_public_values_v2(&mut self, public_values: RecursionPublicValues<Felt<SP1Field>>);
    fn cycle_tracker_v2_enter(&mut self, name: impl Into<Cow<'static, str>>);
    fn cycle_tracker_v2_exit(&mut self);
    fn hint_ext_v2(&mut self) -> Ext<SP1Field, SP1ExtensionField>;
    fn hint_felt_v2(&mut self) -> Felt<SP1Field>;
    fn hint_exts_v2(&mut self, len: usize) -> Vec<Ext<SP1Field, SP1ExtensionField>>;
    fn hint_felts_v2(&mut self, len: usize) -> Vec<Felt<SP1Field>>;
}

impl<C: Config> CircuitV2Builder<C> for Builder<C> {
    fn bits2num_v2_f(&mut self, bits: impl IntoIterator<Item = Felt<SP1Field>>) -> Felt<SP1Field> {
        let mut num: Felt<_> = self.eval(SP1Field::zero());
        for (i, bit) in bits.into_iter().enumerate() {
            // Add `bit * 2^i` to the sum.
            num = self.eval(num + bit * SP1Field::from_wrapped_u32(1 << i));
        }
        num
    }

    /// Converts a felt to bits inside a circuit.
    fn num2bits_v2_f(&mut self, num: Felt<SP1Field>, num_bits: usize) -> Vec<Felt<SP1Field>> {
        let output = std::iter::from_fn(|| Some(self.uninit())).take(num_bits).collect::<Vec<_>>();
        self.push_op(DslIr::CircuitV2HintBitsF(output.clone(), num));

        let x: SymbolicFelt<_> = output
            .iter()
            .enumerate()
            .map(|(i, &bit)| {
                self.assert_felt_eq(bit * (bit - SP1Field::one()), SP1Field::zero());
                bit * SP1Field::from_wrapped_u32(1 << i)
            })
            .sum();

        // Range check the bits to be less than the SP1Field modulus.

        assert!(num_bits <= 31, "num_bits must be less than or equal to 31");

        // If there are less than 31 bits, there is nothing to check.
        if num_bits > 30 {
            // Since SP1Field modulus is 2^31 - 2^24 + 1, if any of the top `7` bits are zero, the
            // number is less than 2^24, and we can stop the iteration. Othwriwse, if all the top
            // `7` bits are '1`, we need to check that all the bottom `24` are '0`

            // Get a flag that is zero if any of the top `7` bits are zero, and one otherwise. We
            // can do this by simply taking their product (which is bitwise AND).
            let are_all_top_bits_one: Felt<_> = self.eval(
                output
                    .iter()
                    .rev()
                    .take(7)
                    .copied()
                    .map(SymbolicFelt::from)
                    .product::<SymbolicFelt<_>>(),
            );

            // Assert that if all the top `7` bits are one, then all the bottom `24` bits are zero.
            for bit in output.iter().take(24).copied() {
                self.assert_felt_eq(bit * are_all_top_bits_one, SP1Field::zero());
            }
        }

        // Check that the original number matches the bit decomposition.
        self.assert_felt_eq(x, num);

        output
    }

    /// A version of the `prefix_sum_checks` that uses the LagrangeEval precompile.
    fn prefix_sum_checks_v2(
        &mut self,
        point_1: Vec<Felt<SP1Field>>,
        point_2: Vec<Ext<SP1Field, SP1ExtensionField>>,
    ) -> (Ext<SP1Field, SP1ExtensionField>, Felt<SP1Field>) {
        let len = point_1.len();
        assert_eq!(point_1.len(), point_2.len());
        // point_1 is current and next prefix sum merged
        assert_eq!(len % 2, 0);
        let output: Vec<Ext<_, _>> = std::iter::from_fn(|| Some(self.uninit())).take(len).collect();
        let field_accs: Vec<Felt<_>> =
            std::iter::from_fn(|| Some(self.uninit())).take(len).collect();
        let one: Ext<_, _> = self.uninit();
        let zero: Felt<_> = self.uninit();
        self.push_op(DslIr::ImmE(one, SP1ExtensionField::one()));
        self.push_op(DslIr::ImmF(zero, SP1Field::zero()));
        self.push_op(DslIr::CircuitV2PrefixSumChecks(Box::new((
            zero,
            one,
            output.clone(),
            field_accs.clone(),
            point_1,
            point_2,
        ))));
        (output[len - 1], field_accs[len / 2 - 1])
    }

    /// Applies the Poseidon2 permutation to the given array.
    fn poseidon2_permute_v2(
        &mut self,
        array: [Felt<SP1Field>; PERMUTATION_WIDTH],
    ) -> [Felt<SP1Field>; PERMUTATION_WIDTH] {
        let output: [Felt<SP1Field>; PERMUTATION_WIDTH] = core::array::from_fn(|_| self.uninit());
        self.push_op(DslIr::CircuitV2Poseidon2PermuteKoalaBear(Box::new((output, array))));
        output
    }

    /// Decomposes an ext into its felt coordinates.
    fn ext2felt_v2(&mut self, ext: Ext<SP1Field, SP1ExtensionField>) -> [Felt<SP1Field>; D] {
        let felts = core::array::from_fn(|_| self.uninit());
        self.push_op(DslIr::CircuitExt2Felt(felts, ext));
        // Verify that the decomposed extension element is correct.
        let mut reconstructed_ext: Ext<SP1Field, SP1ExtensionField> =
            self.constant(SP1ExtensionField::zero());
        for i in 0..4 {
            let felt = felts[i];
            let monomial: Ext<SP1Field, SP1ExtensionField> =
                self.constant(<SP1ExtensionField as AbstractExtensionField<SP1Field>>::monomial(i));
            reconstructed_ext = self.eval(reconstructed_ext + monomial * felt);
        }

        self.assert_ext_eq(reconstructed_ext, ext);

        felts
    }

    /// Adds two septic elliptic curve points.
    fn add_curve_v2(
        &mut self,
        point1: SepticCurve<Felt<SP1Field>>,
        point2: SepticCurve<Felt<SP1Field>>,
    ) -> SepticCurve<Felt<SP1Field>> {
        // Hint the curve addition result.
        let point_sum_x: [Felt<SP1Field>; 7] = core::array::from_fn(|_| self.uninit());
        let point_sum_y: [Felt<SP1Field>; 7] = core::array::from_fn(|_| self.uninit());
        let point =
            SepticCurve { x: SepticExtension(point_sum_x), y: SepticExtension(point_sum_y) };
        self.push_op(DslIr::CircuitV2HintAddCurve(Box::new((point, point1, point2))));

        // Convert each point into a point over SymbolicFelt.
        let point1_symbolic = SepticCurve::convert(point1, |x| x.into());
        let point2_symbolic = SepticCurve::convert(point2, |x| x.into());
        let point_symbolic = SepticCurve::convert(point, |x| x.into());

        // Evaluate `sum_checker_x` and `sum_checker_y`.
        let sum_checker_x = SepticCurve::<SymbolicFelt<SP1Field>>::sum_checker_x(
            point1_symbolic,
            point2_symbolic,
            point_symbolic,
        );

        let sum_checker_y = SepticCurve::<SymbolicFelt<SP1Field>>::sum_checker_y(
            point1_symbolic,
            point2_symbolic,
            point_symbolic,
        );

        // Constrain `sum_checker_x` and `sum_checker_y` to be all zero.
        for limb in sum_checker_x.0 {
            self.assert_felt_eq(limb, SP1Field::zero());
        }

        for limb in sum_checker_y.0 {
            self.assert_felt_eq(limb, SP1Field::zero());
        }

        point
    }

    /// Asserts that the `digest` is the zero digest when `is_real` is non-zero.
    fn assert_digest_zero_v2(
        &mut self,
        is_real: Felt<SP1Field>,
        digest: SepticDigest<Felt<SP1Field>>,
    ) {
        let zero = SepticDigest::<SymbolicFelt<SP1Field>>::zero();
        for (digest_limb_x, zero_limb_x) in digest.0.x.0.into_iter().zip_eq(zero.0.x.0) {
            self.assert_felt_eq(is_real * digest_limb_x, is_real * zero_limb_x);
        }
        for (digest_limb_y, zero_limb_y) in digest.0.y.0.into_iter().zip_eq(zero.0.y.0) {
            self.assert_felt_eq(is_real * digest_limb_y, is_real * zero_limb_y);
        }
    }

    /// Returns the zero digest when `is_first_execution_shard` is zero, and returns the `vk_digest`
    /// when `is_first_execution_shard` is one. It is assumed that `is_first_execution_shard` is
    /// already checked to be a boolean.
    fn select_global_cumulative_sum(
        &mut self,
        is_first_execution_shard: Felt<SP1Field>,
        vk_digest: SepticDigest<Felt<SP1Field>>,
    ) -> SepticDigest<Felt<SP1Field>> {
        let zero = SepticDigest::<SymbolicFelt<SP1Field>>::zero();
        let one: Felt<SP1Field> = self.constant(SP1Field::one());
        let x = SepticExtension(core::array::from_fn(|i| {
            self.eval(
                is_first_execution_shard * vk_digest.0.x.0[i]
                    + (one - is_first_execution_shard) * zero.0.x.0[i],
            )
        }));
        let y = SepticExtension(core::array::from_fn(|i| {
            self.eval(
                is_first_execution_shard * vk_digest.0.y.0[i]
                    + (one - is_first_execution_shard) * zero.0.y.0[i],
            )
        }));
        SepticDigest(SepticCurve { x, y })
    }

    // Sums the digests into one.
    fn sum_digest_v2(
        &mut self,
        digests: Vec<SepticDigest<Felt<SP1Field>>>,
    ) -> SepticDigest<Felt<SP1Field>> {
        let mut convert_to_felt =
            |point: SepticCurve<SP1Field>| SepticCurve::convert(point, |value| self.eval(value));

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
    fn commit_public_values_v2(&mut self, public_values: RecursionPublicValues<Felt<SP1Field>>) {
        self.push_op(DslIr::CircuitV2CommitPublicValues(Box::new(public_values)));
    }

    fn cycle_tracker_v2_enter(&mut self, name: impl Into<Cow<'static, str>>) {
        self.push_op(DslIr::CycleTrackerV2Enter(name.into()));
    }

    fn cycle_tracker_v2_exit(&mut self) {
        self.push_op(DslIr::CycleTrackerV2Exit);
    }

    /// Hint a single felt.
    fn hint_felt_v2(&mut self) -> Felt<SP1Field> {
        self.hint_felts_v2(1)[0]
    }

    /// Hint a single ext.
    fn hint_ext_v2(&mut self) -> Ext<SP1Field, SP1ExtensionField> {
        self.hint_exts_v2(1)[0]
    }

    /// Hint a vector of felts.
    fn hint_felts_v2(&mut self, len: usize) -> Vec<Felt<SP1Field>> {
        let arr = std::iter::from_fn(|| Some(self.uninit())).take(len).collect::<Vec<_>>();
        self.push_op(DslIr::CircuitV2HintFelts(arr[0], len));
        arr
    }

    /// Hint a vector of exts.
    fn hint_exts_v2(&mut self, len: usize) -> Vec<Ext<SP1Field, SP1ExtensionField>> {
        let arr = std::iter::from_fn(|| Some(self.uninit())).take(len).collect::<Vec<_>>();
        self.push_op(DslIr::CircuitV2HintExts(arr[0], len));
        arr
    }
}
