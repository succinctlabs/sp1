use super::fp_op::FpOpCols;
use super::params::{FieldParameters, Limbs};
use crate::air::CurtaAirBuilder;
use crate::operations::field::params::{Ed25519BaseField, NUM_LIMBS};
use crate::utils::ec::edwards::ed25519::ed25519_sqrt;
use crate::utils::ec::edwards::EdwardsParameters;
use crate::{operations, utils};
use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use num::BigUint;
use p3_field::Field;
use std::fmt::Debug;
use valida_derive::AlignedBorrow;

/// A set of columns to compute the square root in the ed25519 curve. `T` is the field in which each
/// limb lives.
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
    /// Populates the trace.
    ///
    /// `P` is the parameter of the field that each limb lives in.
    pub fn populate<P: FieldParameters>(&mut self, a: &BigUint) -> BigUint {
        let result = ed25519_sqrt(a.clone());
        println!("a = {}, result = {}", a, result);

        // Use FpOpCols to compute result * result.
        let result_squared = self.multiplication.populate::<Ed25519BaseField>(
            &result,
            &result,
            super::fp_op::FpOperation::Mul,
        );

        // If the result is indeed the square root of a, then result * result = a.
        assert_eq!(result_squared, a.clone());

        // Double check that `self.multiplication.result` is set correctly.
        let a_limbs = P::to_limbs_field::<F>(a);
        for i in 0..NUM_LIMBS {
            assert_eq!(self.multiplication.result[i], a_limbs[i]);
        }

        result
    }
}

impl<V: Copy> EdSqrtCols<V> {
    /// Calculates the square root of `a` and stores it in `self.result` while verifying that the
    /// result is indeed the square root of `a`.
    pub fn eval<AB: CurtaAirBuilder<Var = V>>(&self, builder: &mut AB, a: &Limbs<AB::Var>)
    where
        V: Into<AB::Expr>,
    {
        // Compute result * result. I'm not sure why, but this seems to fail. I pass in ed25519 base
        // field since i want that to be the mod.
        self.multiplication.eval::<AB, Ed25519BaseField>(
            builder,
            &self.result.clone(),
            &self.result.clone(),
            super::fp_op::FpOperation::Mul,
        );

        // Compare a to the result of self.result * self.result.
        for i in 0..NUM_LIMBS {
            builder.assert_eq(a[i], self.multiplication.result[i]);
        }
    }
}

#[cfg(test)]
mod tests {
    use num::{BigUint, One, Zero};
    use p3_air::BaseAir;
    use p3_challenger::DuplexChallenger;
    use p3_dft::Radix2DitParallel;
    use p3_field::Field;

    use super::{EdSqrtCols, FpOpCols, Limbs};
    use crate::operations::field::fp_op::FpOperation;
    use crate::utils::ec::edwards::ed25519::Ed25519Parameters;
    use crate::utils::ec::edwards::EdwardsParameters;
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
            let mut operands: Vec<BigUint> = (0..num_rows - 2)
                .map(|_| {
                    // Take the square of a random number to make sure that the square root exists.
                    // TODO: Use the RNG here, for debugging purposes, i'm putting a constant.

                    let a = BigUint::zero();
                    let sq = a.clone() * a.clone();
                    // We want to mod by the ed25519 modulus.
                    sq % &Ed25519BaseField::modulus()
                })
                .collect();

            operands.extend(vec![BigUint::zero(), BigUint::one()]);

            let rows = operands
                .iter()
                .map(|a| {
                    let mut row = [F::zero(); NUM_TEST_COLS];
                    let cols: &mut TestCols<F> = unsafe { transmute(&mut row) };
                    cols.a = P::to_limbs_field::<F>(a);
                    // We pass in P = Ed25519BaseField in the test, so I pass it to populate as well.
                    //
                    // Although I'm not sure if this is correct? That's what we do in fp_op.rs, so
                    // I am just trying to follow that to avoid any bugs, but maybe it doesn't work
                    // here? Maybe it makes more sense to pass in babybear?
                    //
                    // TODO: Ask Uma if this is correct. Maybe this is wrong. We need to pass in the
                    // field where each limb lives in?
                    let res = cols.sqrt.populate::<P>(a);
                    println!("within generate_trace, a = {}, res = {}", a, res);
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

            // eval verifies that local.sqrt.result is indeed the square root of local.a.
            local.sqrt.eval::<AB>(builder, &local.a);

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
        // println!("{:?}", trace.values)
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
