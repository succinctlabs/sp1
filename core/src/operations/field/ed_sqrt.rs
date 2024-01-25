use super::fp_op::FpOpCols;
use super::params::{FieldParameters, Limbs};
use crate::air::CurtaAirBuilder;
use crate::operations::field::params::{Ed25519BaseField, NUM_LIMBS};
use crate::utils::ec::edwards::ed25519::ed25519_sqrt;
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
    /// The multiplication operation to verify that the sqrt and the input match.
    ///
    /// In order to save space, we actually store the sqrt of the input in `multiplication.result`
    /// since we'll receive the input again in the `eval` function.
    pub multiplication: FpOpCols<T>,
}

impl<F: Field> EdSqrtCols<F> {
    /// Populates the trace.
    ///
    /// `P` is the parameter of the field that each limb lives in.
    pub fn populate<P: FieldParameters>(&mut self, a: &BigUint) -> BigUint {
        let sqrt = ed25519_sqrt(a.clone());

        // Use FpOpCols to compute result * result.
        let sqrt_squared = self.multiplication.populate::<Ed25519BaseField>(
            &sqrt,
            &sqrt,
            super::fp_op::FpOperation::Mul,
        );

        // If the result is indeed the square root of a, then result * result = a.
        assert_eq!(sqrt_squared, a.clone());

        // This is a hack to save a column in EdSqrtCols. We will receive the value a again in the
        // eval function, so we'll overwrite it with the sqrt.
        // self.multiplication.result = P::to_limbs_field::<F>(&sqrt);
        self.multiplication.result = P::to_limbs_field::<F>(&sqrt);

        sqrt
    }
}

impl<V: Copy> EdSqrtCols<V> {
    /// Calculates the square root of `a`.
    pub fn eval<AB: CurtaAirBuilder<Var = V>>(&self, builder: &mut AB, a: &Limbs<AB::Var>)
    where
        V: Into<AB::Expr>,
    {
        // As a space-saving hack, we store the sqrt of the input in `self.multiplication.result`
        // even though it's technically not the result of the multiplication. Now, we should
        // retrieve that value and overwrite that member variable with a.
        let sqrt = self.multiplication.result;
        let mut multiplication = self.multiplication.clone();
        multiplication.result = *a;

        // Compute sqrt * sqrt. We pass in ed25519 base field since we want that to be the mod.
        multiplication.eval::<AB, Ed25519BaseField>(
            builder,
            &sqrt,
            &sqrt,
            super::fp_op::FpOperation::Mul,
        );
    }
}

#[cfg(test)]
mod tests {
    use num::{BigUint, One, Zero};
    use p3_air::BaseAir;
    use p3_challenger::DuplexChallenger;
    use p3_dft::Radix2DitParallel;
    use p3_field::Field;

    use super::{EdSqrtCols, Limbs};
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
                    let a = rng.gen_biguint(256);
                    let sq = a.clone() * a.clone();
                    // We want to mod by the ed25519 modulus.
                    sq % &Ed25519BaseField::modulus()
                })
                .collect();

            // hardcoded edge cases.
            operands.extend(vec![BigUint::zero(), BigUint::one()]);

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
