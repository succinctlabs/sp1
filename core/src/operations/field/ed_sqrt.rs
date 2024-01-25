use super::fp_op::FpOpCols;
use super::params::{convert_polynomial, convert_vec, FieldParameters, Limbs};
use super::util::{compute_root_quotient_and_shift, split_u16_limbs_to_u8_limbs};
use super::util_air::eval_field_operation;
use crate::air::polynomial::Polynomial;
use crate::air::CurtaAirBuilder;
use crate::operations::field::params::NUM_LIMBS;
use crate::utils::ec::edwards::ed25519::ed25519_sqrt;
use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use num::{BigUint, Zero};
use p3_air::AirBuilder;
use p3_baby_bear::BabyBear;
use p3_field::Field;
use std::fmt::Debug;
use valida_derive::AlignedBorrow;

/// A set of columns to compute the square root in the ed25519 curve.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct EdSqrtCols<T> {
    /// The result of `sqrt(a)`.
    pub result: Limbs<T>,

    // The following columns are used to verify that the product of the result with itself is equal
    // to the input.
    pub multiplication: FpOpCols<T>,
}

impl<F: Field> EdSqrtCols<F> {
    pub fn populate<P: FieldParameters>(&mut self, a: &BigUint) -> BigUint {
        let result = ed25519_sqrt(a.clone());
        println!("a = {}, result = {}", a, result);
        self.multiplication
            .populate::<P>(&result, &result, super::fp_op::FpOperation::Mul);
        result
    }
}

impl<V: Copy> EdSqrtCols<V> {
    pub fn eval<AB: CurtaAirBuilder<Var = V>, P: FieldParameters>(
        &self,
        builder: &mut AB,
        a: &Limbs<AB::Var>,
    ) where
        V: Into<AB::Expr>,
    {
        self.multiplication.eval::<AB, P>(
            builder,
            &self.result,
            &self.result,
            super::fp_op::FpOperation::Mul,
        );

        for i in 0..NUM_LIMBS {
            builder.assert_eq(a[i], self.multiplication.result[i]);
        }
    }
}

#[cfg(test)]
mod tests {
    use num::{BigUint, Zero};
    use p3_air::BaseAir;
    use p3_challenger::DuplexChallenger;
    use p3_dft::Radix2DitParallel;
    use p3_field::Field;

    use super::{EdSqrtCols, FpOpCols, Limbs};
    use crate::operations::field::fp_op::FpOperation;
    use crate::utils::pad_to_power_of_two;
    use crate::{
        air::CurtaAirBuilder,
        operations::field::params::{Ed25519BaseField, FieldParameters},
        runtime::Segment,
        utils::Chip,
    };
    use core::borrow::{Borrow, BorrowMut};
    use core::mem::{size_of, transmute};
    use num::bigint::RandBigInt;
    use p3_air::Air;
    use p3_baby_bear::BabyBear;
    use p3_commit::ExtensionMmcs;
    use p3_field::extension::BinomialExtensionField;
    use p3_fri::{FriBasedPcs, FriConfigImpl, FriLdt};
    use p3_keccak::Keccak256Hash;
    use p3_ldt::QuotientMmcs;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_matrix::MatrixRowSlices;
    use p3_mds::coset_mds::CosetMds;
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_poseidon2::{DiffusionMatrixBabybear, Poseidon2};
    use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
    use p3_uni_stark::{prove, verify, StarkConfigImpl};
    use rand::thread_rng;
    use valida_derive::AlignedBorrow;
    #[derive(AlignedBorrow, Debug, Clone)]
    pub struct TestCols<T> {
        pub a: Limbs<T>,
        pub sqrt: EdSqrtCols<T>,
    }

    pub const NUM_TEST_COLS: usize = size_of::<TestCols<u8>>();

    struct EdSqrtChip<P: FieldParameters> {
        pub _phantom: std::marker::PhantomData<P>,
    }

    impl<P: FieldParameters> EdSqrtChip<P> {
        pub fn new() -> Self {
            Self {
                _phantom: std::marker::PhantomData,
            }
        }
    }

    impl<F: Field, P: FieldParameters> Chip<F> for EdSqrtChip<P> {
        fn name(&self) -> String {
            "EdSqrtChip".to_string()
        }

        fn generate_trace(&self, _: &mut Segment) -> RowMajorMatrix<F> {
            let mut rng = thread_rng();
            let num_rows = 1 << 8;
            let operands: Vec<BigUint> = (0..num_rows)
                .map(|_| {
                    // Take the square of a random number to make sure that the square root exists.
                    let a = BigUint::zero();
                    let sq = a.clone() * a.clone();
                    sq % &P::modulus()
                })
                .collect();

            let rows = operands
                .iter()
                .map(|a| {
                    let mut row = [F::zero(); NUM_TEST_COLS];
                    let cols: &mut TestCols<F> = unsafe { transmute(&mut row) };
                    cols.a = P::to_limbs_field::<F>(a);
                    cols.sqrt.populate::<P>(a);
                    row
                })
                .collect::<Vec<_>>();

            // Convert the trace to a row major matrix.
            let mut trace = RowMajorMatrix::new(
                rows.into_iter().flatten().collect::<Vec<_>>(),
                NUM_TEST_COLS,
            );

            // Pad the trace to a power of two.
            pad_to_power_of_two::<NUM_TEST_COLS, F>(&mut trace.values);

            trace
        }
    }

    impl<F: Field, P: FieldParameters> BaseAir<F> for EdSqrtChip<P> {
        fn width(&self) -> usize {
            NUM_TEST_COLS
        }
    }

    impl<AB, P: FieldParameters> Air<AB> for EdSqrtChip<P>
    where
        AB: CurtaAirBuilder,
    {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local: &TestCols<AB::Var> = main.row_slice(0).borrow();
            local.sqrt.eval::<AB, P>(builder, &local.a);

            // A dummy constraint to keep the degree 3.
            builder.assert_zero(
                local.a[0] * local.a[0] * local.a[0] - local.a[0] * local.a[0] * local.a[0],
            )
        }
    }

    #[test]
    fn generate_trace() {
        let chip: EdSqrtChip<Ed25519BaseField> = EdSqrtChip::new();
        let mut segment = Segment::default();
        let _: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut segment);
    }

    #[test]
    fn prove_babybear() {
        type Val = BabyBear;
        type Domain = Val;
        type Challenge = BinomialExtensionField<Val, 4>;
        type PackedChallenge = BinomialExtensionField<<Domain as Field>::Packing, 4>;

        type MyMds = CosetMds<Val, 16>;
        type Perm = Poseidon2<Val, MyMds, DiffusionMatrixBabybear, 16, 5>;

        type MyHash = SerializingHasher32<Keccak256Hash>;
        let hash = MyHash::new(Keccak256Hash {});

        type MyCompress = CompressionFunctionFromHasher<Val, MyHash, 2, 8>;
        let compress = MyCompress::new(hash);

        type ValMmcs = FieldMerkleTreeMmcs<Val, MyHash, MyCompress, 8>;
        let val_mmcs = ValMmcs::new(hash, compress);

        type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

        type Dft = Radix2DitParallel;
        let dft = Dft {};

        type Challenger = DuplexChallenger<Val, Perm, 16>;

        type Quotient = QuotientMmcs<Domain, Challenge, ValMmcs>;
        type MyFriConfig = FriConfigImpl<Val, Challenge, Quotient, ChallengeMmcs, Challenger>;
        let fri_config = MyFriConfig::new(1, 40, challenge_mmcs);
        let ldt = FriLdt { config: fri_config };

        type Pcs = FriBasedPcs<MyFriConfig, ValMmcs, Dft, Challenger>;
        type MyConfig = StarkConfigImpl<Val, Challenge, PackedChallenge, Pcs, Challenger>;

        let pcs = Pcs::new(dft, val_mmcs, ldt);
        let config = StarkConfigImpl::new(pcs);

        let mds = MyMds::default();
        let perm = Perm::new_from_rng(8, 22, mds, DiffusionMatrixBabybear, &mut thread_rng());
        let mut challenger = Challenger::new(perm.clone());

        let chip: EdSqrtChip<Ed25519BaseField> = EdSqrtChip::new();
        let mut segment = Segment::default();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut segment);
        let proof = prove::<MyConfig, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = Challenger::new(perm.clone());
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
