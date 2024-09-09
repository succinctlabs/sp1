use std::fmt::Debug;

use num::{BigUint, Zero};
use p3_field::{AbstractField, PrimeField32};
use sp1_core_executor::events::ByteRecord;
use sp1_curves::params::{FieldParameters, Limbs};
use sp1_derive::AlignedBorrow;
use sp1_stark::air::{Polynomial, SP1AirBuilder};

use super::{
    util::{compute_root_quotient_and_shift, split_u16_limbs_to_u8_limbs},
    util_air::eval_field_operation,
};
use crate::air::WordAirBuilder;

/// A set of columns to compute `InnerProduct([a], [b])` where a, b are emulated elements.
///
/// *Safety*: The `FieldInnerProductCols` asserts that `result = sum_i a_i * b_i mod M` where
/// `M` is the modulus `P::modulus()` under the assumption that the length of `a` and `b` is small
/// enough so that the vanishing polynomial has limbs bounded by the witness shift. It is the
/// responsibility of the caller to ensure that the length of `a` and `b` is small enough.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FieldInnerProductCols<T, P: FieldParameters> {
    /// The result of `a inner product b`, where a, b are field elements
    pub result: Limbs<T, P::Limbs>,
    pub(crate) carry: Limbs<T, P::Limbs>,
    pub(crate) witness_low: Limbs<T, P::Witness>,
    pub(crate) witness_high: Limbs<T, P::Witness>,
}

impl<F: PrimeField32, P: FieldParameters> FieldInnerProductCols<F, P> {
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecord,
        shard: u32,
        a: &[BigUint],
        b: &[BigUint],
    ) -> BigUint {
        let p_a_vec: Vec<Polynomial<F>> =
            a.iter().map(|x| P::to_limbs_field::<F, _>(x).into()).collect();
        let p_b_vec: Vec<Polynomial<F>> =
            b.iter().map(|x| P::to_limbs_field::<F, _>(x).into()).collect();

        let modulus = &P::modulus();
        let inner_product = a.iter().zip(b.iter()).fold(BigUint::zero(), |acc, (c, d)| acc + c * d);

        let result = &(&inner_product % modulus);
        let carry = &((&inner_product - result) / modulus);
        assert!(result < modulus);
        assert!(carry < &(2u32 * modulus));
        assert_eq!(carry * modulus, inner_product - result);

        let p_modulus: Polynomial<F> = P::to_limbs_field::<F, _>(modulus).into();
        let p_result: Polynomial<F> = P::to_limbs_field::<F, _>(result).into();
        let p_carry: Polynomial<F> = P::to_limbs_field::<F, _>(carry).into();

        // Compute the vanishing polynomial.
        let p_inner_product = p_a_vec
            .into_iter()
            .zip(p_b_vec)
            .fold(Polynomial::<F>::new(vec![F::zero()]), |acc, (c, d)| acc + &c * &d);
        let p_vanishing = p_inner_product - &p_result - &p_carry * &p_modulus;
        assert_eq!(p_vanishing.degree(), P::NB_WITNESS_LIMBS);

        let p_witness = compute_root_quotient_and_shift(
            &p_vanishing,
            P::WITNESS_OFFSET,
            P::NB_BITS_PER_LIMB as u32,
            P::NB_WITNESS_LIMBS,
        );
        let (p_witness_low, p_witness_high) = split_u16_limbs_to_u8_limbs(&p_witness);

        self.result = p_result.into();
        self.carry = p_carry.into();
        self.witness_low = Limbs(p_witness_low.try_into().unwrap());
        self.witness_high = Limbs(p_witness_high.try_into().unwrap());

        // Range checks
        record.add_u8_range_checks_field(shard, &self.result.0);
        record.add_u8_range_checks_field(shard, &self.carry.0);
        record.add_u8_range_checks_field(shard, &self.witness_low.0);
        record.add_u8_range_checks_field(shard, &self.witness_high.0);

        result.clone()
    }
}

impl<V: Copy, P: FieldParameters> FieldInnerProductCols<V, P>
where
    Limbs<V, P::Limbs>: Copy,
{
    pub fn eval<AB: SP1AirBuilder<Var = V>>(
        &self,
        builder: &mut AB,
        a: &[Limbs<AB::Var, P::Limbs>],
        b: &[Limbs<AB::Var, P::Limbs>],
        is_real: impl Into<AB::Expr> + Clone,
    ) where
        V: Into<AB::Expr>,
    {
        let p_a_vec: Vec<Polynomial<AB::Expr>> = a.iter().map(|x| (*x).into()).collect();
        let p_b_vec: Vec<Polynomial<AB::Expr>> = b.iter().map(|x| (*x).into()).collect();
        let p_result = self.result.into();
        let p_carry = self.carry.into();

        let p_zero = Polynomial::<AB::Expr>::new(vec![AB::Expr::zero()]);

        let p_inner_product = p_a_vec
            .iter()
            .zip(p_b_vec.iter())
            .map(|(p_a, p_b)| p_a * p_b)
            .collect::<Vec<_>>()
            .iter()
            .fold(p_zero, |acc, x| acc + x);

        let p_inner_product_minus_result = &p_inner_product - &p_result;
        let p_limbs = Polynomial::from_iter(P::modulus_field_iter::<AB::F>().map(AB::Expr::from));
        let p_vanishing = &p_inner_product_minus_result - &(&p_carry * &p_limbs);

        let p_witness_low = self.witness_low.0.iter().into();
        let p_witness_high = self.witness_high.0.iter().into();

        eval_field_operation::<AB, P>(builder, &p_vanishing, &p_witness_low, &p_witness_high);

        // Range checks for the result, carry, and witness columns.
        builder.slice_range_check_u8(&self.result.0, is_real.clone());
        builder.slice_range_check_u8(&self.carry.0, is_real.clone());
        builder.slice_range_check_u8(&self.witness_low.0, is_real.clone());
        builder.slice_range_check_u8(&self.witness_high.0, is_real);
    }
}

#[cfg(test)]
mod tests {
    use num::BigUint;
    use p3_air::BaseAir;
    use p3_field::{Field, PrimeField32};
    use sp1_core_executor::{ExecutionRecord, Program};
    use sp1_curves::params::FieldParameters;
    use sp1_stark::air::{MachineAir, SP1AirBuilder};

    use super::{FieldInnerProductCols, Limbs};

    use crate::utils::{pad_to_power_of_two, uni_stark_prove as prove, uni_stark_verify as verify};
    use core::{
        borrow::{Borrow, BorrowMut},
        mem::size_of,
    };
    use num::bigint::RandBigInt;
    use p3_air::Air;
    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use p3_matrix::{dense::RowMajorMatrix, Matrix};
    use rand::thread_rng;
    use sp1_curves::edwards::ed25519::Ed25519BaseField;
    use sp1_derive::AlignedBorrow;
    use sp1_stark::{baby_bear_poseidon2::BabyBearPoseidon2, StarkGenericConfig};

    #[derive(AlignedBorrow, Debug, Clone)]
    pub struct TestCols<T, P: FieldParameters> {
        pub a: [Limbs<T, P::Limbs>; 1],
        pub b: [Limbs<T, P::Limbs>; 1],
        pub a_ip_b: FieldInnerProductCols<T, P>,
    }

    pub const NUM_TEST_COLS: usize = size_of::<TestCols<u8, Ed25519BaseField>>();

    struct FieldIpChip<P: FieldParameters> {
        pub _phantom: std::marker::PhantomData<P>,
    }

    impl<P: FieldParameters> FieldIpChip<P> {
        pub const fn new() -> Self {
            Self { _phantom: std::marker::PhantomData }
        }
    }

    impl<F: PrimeField32, P: FieldParameters> MachineAir<F> for FieldIpChip<P> {
        type Record = ExecutionRecord;

        type Program = Program;

        fn name(&self) -> String {
            "FieldInnerProduct".to_string()
        }

        fn generate_trace(
            &self,
            _: &ExecutionRecord,
            output: &mut ExecutionRecord,
        ) -> RowMajorMatrix<F> {
            let mut rng = thread_rng();
            let num_rows = 1 << 8;
            let mut operands: Vec<(Vec<BigUint>, Vec<BigUint>)> = (0..num_rows - 4)
                .map(|_| {
                    let a = rng.gen_biguint(256) % &P::modulus();
                    let b = rng.gen_biguint(256) % &P::modulus();
                    (vec![a], vec![b])
                })
                .collect();

            operands.extend(vec![
                (vec![BigUint::from(0u32)], vec![BigUint::from(0u32)]),
                (vec![BigUint::from(0u32)], vec![BigUint::from(0u32)]),
                (vec![BigUint::from(0u32)], vec![BigUint::from(0u32)]),
                (vec![BigUint::from(0u32)], vec![BigUint::from(0u32)]),
            ]);
            let rows = operands
                .iter()
                .map(|(a, b)| {
                    let mut row = [F::zero(); NUM_TEST_COLS];
                    let cols: &mut TestCols<F, P> = row.as_mut_slice().borrow_mut();
                    cols.a[0] = P::to_limbs_field::<F, _>(&a[0]);
                    cols.b[0] = P::to_limbs_field::<F, _>(&b[0]);
                    cols.a_ip_b.populate(output, 1, a, b);
                    row
                })
                .collect::<Vec<_>>();
            // Convert the trace to a row major matrix.
            let mut trace =
                RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_TEST_COLS);

            // Pad the trace to a power of two.
            pad_to_power_of_two::<NUM_TEST_COLS, F>(&mut trace.values);

            trace
        }

        fn included(&self, _: &Self::Record) -> bool {
            true
        }
    }

    impl<F: Field, P: FieldParameters> BaseAir<F> for FieldIpChip<P> {
        fn width(&self) -> usize {
            NUM_TEST_COLS
        }
    }

    impl<AB, P: FieldParameters> Air<AB> for FieldIpChip<P>
    where
        AB: SP1AirBuilder,
        Limbs<AB::Var, P::Limbs>: Copy,
    {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local = main.row_slice(0);
            let local: &TestCols<AB::Var, P> = (*local).borrow();
            local.a_ip_b.eval(builder, &local.a, &local.b, AB::F::one());
        }
    }

    #[test]
    fn generate_trace() {
        let shard = ExecutionRecord::default();
        let chip: FieldIpChip<Ed25519BaseField> = FieldIpChip::new();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let shard = ExecutionRecord::default();

        let chip: FieldIpChip<Ed25519BaseField> = FieldIpChip::new();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
