use super::params::Limbs;
use super::params::NUM_WITNESS_LIMBS;
use super::util::{compute_root_quotient_and_shift, split_u16_limbs_to_u8_limbs};
use super::util_air::eval_field_operation;
use crate::air::Polynomial;
use crate::air::SP1AirBuilder;
use crate::utils::ec::field::FieldParameters;
use core::mem::size_of;
use num::BigUint;
use p3_field::PrimeField32;
use sp1_derive::AlignedBorrow;
use std::fmt::Debug;

/// A set of columns to compute `FieldDen(a, b)` where `a`, `b` are field elements.
///
/// `a / (1 + b)` if `sign`
/// `a / -b` if `!sign`
///
/// Right now the number of limbs is assumed to be a constant, although this could be macro-ed
/// or made generic in the future.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FieldDenCols<T> {
    /// The result of `a den b`, where a, b are field elements
    pub result: Limbs<T>,
    pub(crate) carry: Limbs<T>,
    pub(crate) witness_low: [T; NUM_WITNESS_LIMBS],
    pub(crate) witness_high: [T; NUM_WITNESS_LIMBS],
}

impl<F: PrimeField32> FieldDenCols<F> {
    pub fn populate<P: FieldParameters>(
        &mut self,
        a: &BigUint,
        b: &BigUint,
        sign: bool,
    ) -> BigUint {
        let p = P::modulus();
        let minus_b_int = &p - b;
        let b_signed = if sign { b.clone() } else { minus_b_int };
        let denominator = (b_signed + 1u32) % &(p.clone());
        let den_inv = denominator.modpow(&(&p - 2u32), &p);
        let result = (a * &den_inv) % &p;
        debug_assert_eq!(&den_inv * &denominator % &p, BigUint::from(1u32));
        debug_assert!(result < p);

        let equation_lhs = if sign {
            b * &result + &result
        } else {
            b * &result + a
        };
        let equation_rhs = if sign { a.clone() } else { result.clone() };
        let carry = (&equation_lhs - &equation_rhs) / &p;
        debug_assert!(carry < p);
        debug_assert_eq!(&carry * &p, &equation_lhs - &equation_rhs);

        let p_a: Polynomial<F> = P::to_limbs_field::<F>(a).into();
        let p_b: Polynomial<F> = P::to_limbs_field::<F>(b).into();
        let p_p: Polynomial<F> = P::to_limbs_field::<F>(&p).into();
        let p_result: Polynomial<F> = P::to_limbs_field::<F>(&result).into();
        let p_carry: Polynomial<F> = P::to_limbs_field::<F>(&carry).into();

        // Compute the vanishing polynomial.
        let vanishing_poly = if sign {
            &p_b * &p_result + &p_result - &p_a - &p_carry * &p_p
        } else {
            &p_b * &p_result + &p_a - &p_result - &p_carry * &p_p
        };
        debug_assert_eq!(vanishing_poly.degree(), P::NB_WITNESS_LIMBS);

        let p_witness = compute_root_quotient_and_shift(
            &vanishing_poly,
            P::WITNESS_OFFSET,
            P::NB_BITS_PER_LIMB as u32,
        );
        let (p_witness_low, p_witness_high) = split_u16_limbs_to_u8_limbs(&p_witness);

        self.result = p_result.into();
        self.carry = p_carry.into();
        self.witness_low = p_witness_low.try_into().unwrap();
        self.witness_high = p_witness_high.try_into().unwrap();

        result
    }
}

impl<V: Copy> FieldDenCols<V> {
    #[allow(unused_variables)]
    pub fn eval<AB: SP1AirBuilder<Var = V>, P: FieldParameters>(
        &self,
        builder: &mut AB,
        a: &Limbs<AB::Var>,
        b: &Limbs<AB::Var>,
        sign: bool,
    ) where
        V: Into<AB::Expr>,
    {
        let p_a = Polynomial::from(*a);
        let p_b = (*b).into();
        let p_result = self.result.into();
        let p_carry = self.carry.into();

        // Compute the vanishing polynomial:
        //      lhs(x) = sign * (b(x) * result(x) + result(x)) + (1 - sign) * (b(x) * result(x) + a(x))
        //      rhs(x) = sign * a(x) + (1 - sign) * result(x)
        //      lhs(x) - rhs(x) - carry(x) * p(x)
        let p_equation_lhs = if sign {
            &p_b * &p_result + &p_result
        } else {
            &p_b * &p_result + &p_a
        };
        let p_equation_rhs = if sign { p_a } else { p_result };

        let p_lhs_minus_rhs = &p_equation_lhs - &p_equation_rhs;
        let p_limbs = Polynomial::from_iter(P::modulus_field_iter::<AB::F>().map(AB::Expr::from));

        let p_vanishing = p_lhs_minus_rhs - &p_carry * &p_limbs;

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

    use super::{FieldDenCols, Limbs};

    use crate::air::MachineAir;

    use crate::utils::ec::edwards::ed25519::Ed25519BaseField;
    use crate::utils::ec::field::FieldParameters;
    use crate::utils::{uni_stark_prove as prove, uni_stark_verify as verify};
    use crate::utils::{BabyBearPoseidon2, StarkUtils};
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
        pub a: Limbs<T>,
        pub b: Limbs<T>,
        pub a_den_b: FieldDenCols<T>,
    }

    pub const NUM_TEST_COLS: usize = size_of::<TestCols<u8>>();

    struct FieldDenChip<P: FieldParameters> {
        pub sign: bool,
        pub _phantom: std::marker::PhantomData<P>,
    }

    impl<P: FieldParameters> FieldDenChip<P> {
        pub fn new(sign: bool) -> Self {
            Self {
                sign,
                _phantom: std::marker::PhantomData,
            }
        }
    }

    impl<F: PrimeField32, P: FieldParameters> MachineAir<F> for FieldDenChip<P> {
        fn name(&self) -> String {
            "FieldDen".to_string()
        }

        fn generate_trace(
            &self,
            _: &ExecutionRecord,
            _: &mut ExecutionRecord,
        ) -> RowMajorMatrix<F> {
            let mut rng = thread_rng();
            let num_rows = 1 << 8;
            let mut operands: Vec<(BigUint, BigUint)> = (0..num_rows - 4)
                .map(|_| {
                    let a = rng.gen_biguint(256) % &P::modulus();
                    let b = rng.gen_biguint(256) % &P::modulus();
                    (a, b)
                })
                .collect();
            // Hardcoded edge cases.
            operands.extend(vec![
                (BigUint::from(0u32), BigUint::from(0u32)),
                (BigUint::from(1u32), BigUint::from(2u32)),
                (BigUint::from(4u32), BigUint::from(5u32)),
                (BigUint::from(10u32), BigUint::from(19u32)),
            ]);
            // It is important that the number of rows is an exact power of 2,
            // otherwise the padding will not work correctly.
            assert_eq!(operands.len(), num_rows);

            let rows = operands
                .iter()
                .map(|(a, b)| {
                    let mut row = [F::zero(); NUM_TEST_COLS];
                    let cols: &mut TestCols<F> = row.as_mut_slice().borrow_mut();
                    cols.a = P::to_limbs_field::<F>(a);
                    cols.b = P::to_limbs_field::<F>(b);
                    cols.a_den_b.populate::<P>(a, b, self.sign);
                    row
                })
                .collect::<Vec<_>>();
            // Convert the trace to a row major matrix.

            // Note we do not pad the trace here because we cannot just pad with all 0s.

            RowMajorMatrix::new(
                rows.into_iter().flatten().collect::<Vec<_>>(),
                NUM_TEST_COLS,
            )
        }
    }

    impl<F: Field, P: FieldParameters> BaseAir<F> for FieldDenChip<P> {
        fn width(&self) -> usize {
            NUM_TEST_COLS
        }
    }

    impl<AB, P: FieldParameters> Air<AB> for FieldDenChip<P>
    where
        AB: SP1AirBuilder,
    {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local: &TestCols<AB::Var> = main.row_slice(0).borrow();
            local
                .a_den_b
                .eval::<AB, P>(builder, &local.a, &local.b, self.sign);

            // A dummy constraint to keep the degree 3.
            builder.assert_zero(
                local.a[0] * local.b[0] * local.a[0] - local.a[0] * local.b[0] * local.a[0],
            )
        }
    }

    #[test]
    fn generate_trace() {
        let shard = ExecutionRecord::default();
        let chip: FieldDenChip<Ed25519BaseField> = FieldDenChip::new(true);
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let shard = ExecutionRecord::default();

        let chip: FieldDenChip<Ed25519BaseField> = FieldDenChip::new(true);
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        // This it to test that the proof DOESN'T work if messed up.
        // let row = trace.row_mut(0);
        // row[0] = BabyBear::from_canonical_u8(0);
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut challenger, trace);

        let mut challenger = config.challenger();
        verify(&config, &chip, &mut challenger, &proof).unwrap();
    }
}
