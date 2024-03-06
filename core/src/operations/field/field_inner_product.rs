use super::params::Limbs;
use super::params::NUM_WITNESS_LIMBS;
use super::util::{compute_root_quotient_and_shift, split_u16_limbs_to_u8_limbs};
use super::util_air::eval_field_operation;
use crate::air::Polynomial;
use crate::air::SP1AirBuilder;
use crate::utils::ec::field::FieldParameters;
use core::mem::size_of;
use num::BigUint;
use num::Zero;
use p3_field::{AbstractField, PrimeField32};
use sp1_derive::AlignedBorrow;
use std::fmt::Debug;

/// A set of columns to compute `FieldInnerProduct(Vec<a>, Vec<b>)` where a, b are field elements.
/// Right now the number of limbs is assumed to be a constant, although this could be macro-ed
/// or made generic in the future.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FieldInnerProductCols<T> {
    /// The result of `a inner product b`, where a, b are field elements
    pub result: Limbs<T>,
    pub(crate) carry: Limbs<T>,
    pub(crate) witness_low: [T; NUM_WITNESS_LIMBS],
    pub(crate) witness_high: [T; NUM_WITNESS_LIMBS],
}

impl<F: PrimeField32> FieldInnerProductCols<F> {
    pub fn populate<P: FieldParameters>(&mut self, a: &[BigUint], b: &[BigUint]) -> BigUint {
        let p_a_vec: Vec<Polynomial<F>> =
            a.iter().map(|x| P::to_limbs_field::<F>(x).into()).collect();
        let p_b_vec: Vec<Polynomial<F>> =
            b.iter().map(|x| P::to_limbs_field::<F>(x).into()).collect();

        let modulus = &P::modulus();
        let inner_product = a
            .iter()
            .zip(b.iter())
            .fold(BigUint::zero(), |acc, (c, d)| acc + c * d);

        let result = &(&inner_product % modulus);
        let carry = &((&inner_product - result) / modulus);
        assert!(result < modulus);
        assert!(carry < &(2u32 * modulus));
        assert_eq!(carry * modulus, inner_product - result);

        let p_modulus: Polynomial<F> = P::to_limbs_field::<F>(modulus).into();
        let p_result: Polynomial<F> = P::to_limbs_field::<F>(result).into();
        let p_carry: Polynomial<F> = P::to_limbs_field::<F>(carry).into();

        // Compute the vanishing polynomial.
        let p_inner_product = p_a_vec
            .into_iter()
            .zip(p_b_vec)
            .fold(Polynomial::<F>::new(vec![F::zero()]), |acc, (c, d)| {
                acc + &c * &d
            });
        let p_vanishing = p_inner_product - &p_result - &p_carry * &p_modulus;
        assert_eq!(p_vanishing.degree(), P::NB_WITNESS_LIMBS);

        let p_witness = compute_root_quotient_and_shift(
            &p_vanishing,
            P::WITNESS_OFFSET,
            P::NB_BITS_PER_LIMB as u32,
        );
        let (p_witness_low, p_witness_high) = split_u16_limbs_to_u8_limbs(&p_witness);

        self.result = p_result.into();
        self.carry = p_carry.into();
        self.witness_low = p_witness_low.try_into().unwrap();
        self.witness_high = p_witness_high.try_into().unwrap();

        result.clone()
    }
}

impl<V: Copy> FieldInnerProductCols<V> {
    #[allow(unused_variables)]
    pub fn eval<AB: SP1AirBuilder<Var = V>, P: FieldParameters>(
        &self,
        builder: &mut AB,
        a: &[Limbs<AB::Var>],
        b: &[Limbs<AB::Var>],
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
        let p_carry_mul_modulus = &p_carry * &p_limbs;
        let p_vanishing = &p_inner_product_minus_result - &(&p_carry * &p_limbs);

        let p_witness_low = self.witness_low.iter().into();
        let p_witness_high = self.witness_high.iter().into();

        eval_field_operation::<AB, P>(builder, &p_vanishing, &p_witness_low, &p_witness_high);
    }
}

#[cfg(test)]
mod tests {
    use num::BigUint;
    use p3_air::BaseAir;
    use p3_field::{Field, PrimeField32};

    use super::{FieldInnerProductCols, Limbs};

    use crate::air::MachineAir;

    use crate::utils::ec::edwards::ed25519::Ed25519BaseField;
    use crate::utils::ec::field::FieldParameters;
    use crate::utils::{pad_to_power_of_two, BabyBearPoseidon2, StarkUtils};
    use crate::utils::{uni_stark_prove as prove, uni_stark_verify as verify};
    use crate::{air::SP1AirBuilder, runtime::ExecutionRecord};
    use core::borrow::{Borrow, BorrowMut};
    use core::mem::size_of;
    use num::bigint::RandBigInt;
    use p3_air::Air;
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_matrix::MatrixRowSlices;
    use rand::thread_rng;
    use sp1_derive::AlignedBorrow;

    #[derive(AlignedBorrow, Debug, Clone)]
    pub struct TestCols<T> {
        pub a: [Limbs<T>; 1],
        pub b: [Limbs<T>; 1],
        pub a_ip_b: FieldInnerProductCols<T>,
    }

    pub const NUM_TEST_COLS: usize = size_of::<TestCols<u8>>();

    struct FieldIpChip<P: FieldParameters> {
        pub _phantom: std::marker::PhantomData<P>,
    }

    impl<P: FieldParameters> FieldIpChip<P> {
        pub fn new() -> Self {
            Self {
                _phantom: std::marker::PhantomData,
            }
        }
    }

    impl<F: PrimeField32, P: FieldParameters> MachineAir<F> for FieldIpChip<P> {
        fn name(&self) -> String {
            "FieldInnerProduct".to_string()
        }

        fn generate_trace(
            &self,
            _: &ExecutionRecord,
            _: &mut ExecutionRecord,
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
                    let cols: &mut TestCols<F> = row.as_mut_slice().borrow_mut();
                    cols.a[0] = P::to_limbs_field::<F>(&a[0]);
                    cols.b[0] = P::to_limbs_field::<F>(&b[0]);
                    cols.a_ip_b.populate::<P>(a, b);
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

    impl<F: Field, P: FieldParameters> BaseAir<F> for FieldIpChip<P> {
        fn width(&self) -> usize {
            NUM_TEST_COLS
        }
    }

    impl<AB, P: FieldParameters> Air<AB> for FieldIpChip<P>
    where
        AB: SP1AirBuilder,
    {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local: &TestCols<AB::Var> = main.row_slice(0).borrow();
            local.a_ip_b.eval::<AB, P>(builder, &local.a, &local.b);

            // A dummy constraint to keep the degree 3.
            builder.assert_zero(
                local.a[0][0] * local.b[0][0] * local.a[0][0]
                    - local.a[0][0] * local.b[0][0] * local.a[0][0],
            )
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
