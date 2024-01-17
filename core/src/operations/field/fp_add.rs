use super::params::NUM_LIMBS;
use super::params::{convert_polynomial, convert_vec, FieldParameters, Limbs};
use super::util::{compute_root_quotient_and_shift, split_u16_limbs_to_u8_limbs};
use super::util_air::eval_field_operation;
use crate::air::polynomial::Polynomial;
use crate::air::CurtaAirBuilder;
use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use num::BigUint;
use p3_baby_bear::BabyBear;
use p3_field::{Field, PrimeField, PrimeField32};
use std::fmt::Debug;
use valida_derive::AlignedBorrow;

#[derive(PartialEq)]
pub enum FpOperation {
    Add,
    Mul,
    Sub,
}

/// A set of columns to compute `a + b` where a, b are field elements.
/// In the future, this will be macro-ed to support different fields.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FpOpCols<T> {
    /// The result of `a op b`, where a, b are field elements
    pub result: Limbs<T>,
    pub(crate) carry: Limbs<T>,
    pub(crate) witness_low: [T; NUM_LIMBS], // TODO: this number will be macro-ed later
    pub(crate) witness_high: [T; NUM_LIMBS],
}

impl<F: Field> FpOpCols<F> {
    pub fn populate<P: FieldParameters>(
        &mut self,
        a: BigUint,
        b: BigUint,
        op: FpOperation,
    ) -> BigUint {
        type PF = BabyBear;

        let modulus = P::modulus();
        // If sub, a - b = result, equivalent to a = result + b.
        if op == FpOperation::Sub {
            let result = (&a - &b) % &modulus;
            // We populate the carry, witness_low, witness_high as if we were doing an addition with result + b.
            // But we populate `result` with the actual result of the subtraction because those columns are expected
            // to contain the result by the user.
            self.populate::<P>(result.clone(), b, FpOperation::Add);
            let p_result: Polynomial<PF> = P::to_limbs_field::<PF>(&result).into();
            self.result = convert_polynomial(p_result);
            return result;
        }

        let p_a: Polynomial<PF> = P::to_limbs_field::<PF>(&a).into();
        let p_b: Polynomial<PF> = P::to_limbs_field::<PF>(&b).into();

        // Compute field addition in the integers.
        let modulus = P::modulus();
        let (result, carry) = match op {
            FpOperation::Add => (
                (&a + &b) % &modulus,
                (&a + &b - (&a + &b) % &modulus) / &modulus,
            ),
            FpOperation::Mul => (
                (&a * &b) % &modulus,
                (&a * &b - (&a * &b) % &modulus) / &modulus,
            ),
            FpOperation::Sub => unreachable!(),
        };
        debug_assert!(result < modulus);
        debug_assert!(carry < modulus);
        debug_assert_eq!(&carry * &modulus, a + b - &result);

        // Make little endian polynomial limbs.
        let p_modulus: Polynomial<PF> = P::to_limbs_field::<PF>(&modulus).into();
        let p_result: Polynomial<PF> = P::to_limbs_field::<PF>(&result).into();
        let p_carry: Polynomial<PF> = P::to_limbs_field::<PF>(&carry).into();

        // Compute the vanishing polynomial.
        let p_op = match op {
            FpOperation::Add => &p_a + &p_b,
            FpOperation::Mul => &p_a * &p_b,
            FpOperation::Sub => unreachable!(),
        };
        let p_vanishing: Polynomial<PF> = &p_op - &p_result - &p_carry * &p_modulus;
        debug_assert_eq!(p_vanishing.degree(), P::NB_WITNESS_LIMBS);

        let p_witness = compute_root_quotient_and_shift(
            &p_vanishing,
            P::WITNESS_OFFSET,
            P::NB_BITS_PER_LIMB as u32,
        );
        let (p_witness_low, p_witness_high) = split_u16_limbs_to_u8_limbs(&p_witness);

        self.result = convert_polynomial(p_result);
        self.carry = convert_polynomial(p_carry);
        self.witness_low = convert_vec(p_witness_low).0;
        self.witness_high = convert_vec(p_witness_high).0;

        result
    }

    #[allow(unused_variables)]
    pub fn eval<AB: CurtaAirBuilder<F = F>, P: FieldParameters>(
        &self,
        builder: &mut AB,
        // TODO: will have to macro these later
        a: Limbs<AB::Var>,
        b: Limbs<AB::Var>,
        op: FpOperation,
    ) {
        let (p_a, p_result) = match op {
            FpOperation::Add | FpOperation::Mul => (a.into(), self.result.clone().into()),
            FpOperation::Sub => (self.result.clone().into(), a.into()),
        };

        let p_b = b.into();
        let p_carry = self.carry.clone().into();
        let p_op = match op {
            FpOperation::Add | FpOperation::Sub => builder.poly_add(&p_a, &p_b),
            FpOperation::Mul => builder.poly_mul(&p_a, &p_b),
        };
        let p_op_minus_result = builder.poly_sub(&p_op, &p_result);
        let p_limbs = builder.constant_poly(&Polynomial::from_iter(P::modulus_field_iter::<F>()));

        let p_mul_times_carry = builder.poly_mul(&p_carry, &p_limbs);
        let p_vanishing = builder.poly_sub(&p_op_minus_result, &p_mul_times_carry);

        let p_witness_low = self.witness_low.iter().into();
        let p_witness_high = self.witness_high.iter().into();

        eval_field_operation::<AB, P>(builder, &p_vanishing, &p_witness_low, &p_witness_high);
    }
}

#[cfg(test)]
mod tests {
    use p3_air::BaseAir;
    use p3_challenger::DuplexChallenger;
    use p3_dft::Radix2DitParallel;
    use p3_field::Field;

    use super::{FpOpCols, FpOperation, Limbs};
    use crate::{
        air::CurtaAirBuilder,
        alu::AluEvent,
        operations::field::params::{Ed25519BaseField, FieldParameters},
        runtime::{Opcode, Segment},
        utils::Chip,
    };
    use core::borrow::{Borrow, BorrowMut};
    use core::mem::{size_of, transmute};
    use p3_air::Air;
    use p3_baby_bear::BabyBear;
    use p3_commit::ExtensionMmcs;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::PrimeField32;
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
    use rand::{thread_rng, Rng};
    use valida_derive::AlignedBorrow;

    #[derive(AlignedBorrow)]
    pub struct TestCols<T> {
        pub a: Limbs<T>,
        pub b: Limbs<T>,
        pub a_op_b: FpOpCols<T>,
    }

    pub const NUM_TEST_COLS: usize = size_of::<TestCols<u8>>();

    struct FpOpChip<P: FieldParameters> {
        pub operation: FpOperation,
        pub _phantom: std::marker::PhantomData<P>,
    }

    impl<P: FieldParameters> FpOpChip<P> {
        pub fn new(operation: FpOperation) -> Self {
            Self {
                operation,
                _phantom: std::marker::PhantomData,
            }
        }
    }

    impl<F: Field, P: FieldParameters> Chip<F> for FpOpChip<P> {
        fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
            todo!();
        }
    }

    impl<F: Field, P: FieldParameters> BaseAir<F> for FpOpChip<P> {
        fn width(&self) -> usize {
            NUM_TEST_COLS
        }
    }

    impl<AB, P: FieldParameters> Air<AB> for FpOpChip<P>
    where
        AB: CurtaAirBuilder,
    {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local: &TestCols<AB::Var> = main.row_slice(0).borrow();

            // let a = local.a;
            // let b = local[1];
            // let a_op_b = local[2];

            local
                .a_op_b
                .eval::<AB, P>(builder, local.a, local.b, self.operation);
        }
    }

    #[test]
    fn generate_trace() {
        let mut segment = Segment::default();
        segment.add_events = vec![AluEvent::new(0, Opcode::ADD, 14, 8, 6)];
        let chip: FpOpChip<Ed25519BaseField> = FpOpChip::new(FpOperation::Add);
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut segment);
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_babybear() {
        type Val = BabyBear;
        type Domain = Val;
        type Challenge = BinomialExtensionField<Val, 4>;
        type PackedChallenge = BinomialExtensionField<<Domain as Field>::Packing, 4>;

        type MyMds = CosetMds<Val, 16>;
        let mds = MyMds::default();

        type Perm = Poseidon2<Val, MyMds, DiffusionMatrixBabybear, 16, 5>;
        let perm = Perm::new_from_rng(8, 22, mds, DiffusionMatrixBabybear, &mut thread_rng());

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
        let fri_config = MyFriConfig::new(40, challenge_mmcs);
        let ldt = FriLdt { config: fri_config };

        type Pcs = FriBasedPcs<MyFriConfig, ValMmcs, Dft, Challenger>;
        type MyConfig = StarkConfigImpl<Val, Challenge, PackedChallenge, Pcs, Challenger>;

        let pcs = Pcs::new(dft, val_mmcs, ldt);
        let config = StarkConfigImpl::new(pcs);
        let mut challenger = Challenger::new(perm.clone());

        let mut segment = Segment::default();
        for _i in 0..1000 {
            let operand_1 = thread_rng().gen_range(0..u32::MAX);
            let operand_2 = thread_rng().gen_range(0..u32::MAX);
            let result = operand_1.wrapping_add(operand_2);

            segment
                .add_events
                .push(AluEvent::new(0, Opcode::ADD, result, operand_1, operand_2));
        }

        // let chip = AddChip::new();
        // let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut segment);
        // let proof = prove::<MyConfig, _>(&config, &chip, &mut challenger, trace);

        // let mut challenger = Challenger::new(perm);
        // verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
