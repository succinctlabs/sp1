use crate::air::CurtaAirBuilder;
use crate::operations::field::params::AffinePoint;
use crate::operations::field::params::FieldParameters;

use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

use p3_field::Field;
use std::fmt::Debug;
use valida_derive::AlignedBorrow;

use super::ed_add::EdAddCols;

/// A set of columns to compute `FpInnerProduct(Vec<a>, Vec<b>)` where a, b are field elements.
/// Right now the number of limbs is assumed to be a constant, although this could be macro-ed
/// or made generic in the future.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct EdScalarMulCols<T> {
    /// The result of `a inner product b`, where a, b are field elements
    // pub result: AffinePoint<T>,
    pub cycle: T,
    pub bit: T,
    pub temp: AffinePoint<T>,
    pub result: AffinePoint<T>,
    pub result_plus_temp: EdAddCols<T>,
    pub temp_double: EdAddCols<T>,
    pub result_next: AffinePoint<T>, // TODO: we may not need this?
}

// impl<T> EdAddCols<T> {
//     pub fn result(&self) -> AffinePoint<T> {
//         AffinePoint {
//             x: self.x3_ins.result,
//             y: self.y3_ins.result,
//         }
//     }
// }

impl<F: Field> EdScalarMulCols<F> {
    // pub fn populate<P: FieldParameters>(&mut self, a: &Vec<BigUint>, b: &Vec<BigUint>) -> BigUint {
    //     /// TODO: This operation relies on `F` being a PrimeField32, but our traits do not
    //     /// support that. This is a hack, since we always use BabyBear, to get around that, but
    //     /// all operations using "PF" should use "F" in the future.
    //     type PF = BabyBear;

    //     let p_a_vec: Vec<Polynomial<PF>> = a
    //         .iter()
    //         .map(|x| P::to_limbs_field::<PF>(x).into())
    //         .collect();
    //     let p_b_vec: Vec<Polynomial<PF>> = b
    //         .iter()
    //         .map(|x| P::to_limbs_field::<PF>(x).into())
    //         .collect();

    //     let modulus = &P::modulus();
    //     let inner_product = a
    //         .iter()
    //         .zip(b.iter())
    //         .fold(BigUint::zero(), |acc, (c, d)| acc + c * d);

    //     let result = &(&inner_product % modulus);
    //     let carry = &((&inner_product - result) / modulus);
    //     assert!(result < modulus);
    //     assert!(carry < &(2u32 * modulus));
    //     assert_eq!(carry * modulus, inner_product - result);

    //     let p_modulus: Polynomial<PF> = P::to_limbs_field::<PF>(modulus).into();
    //     let p_result: Polynomial<PF> = P::to_limbs_field::<PF>(&result).into();
    //     let p_carry: Polynomial<PF> = P::to_limbs_field::<PF>(&carry).into();

    //     // Compute the vanishing polynomial.
    //     let p_inner_product = p_a_vec.into_iter().zip(p_b_vec).fold(
    //         Polynomial::<PF>::from_coefficients(vec![PF::zero()]),
    //         |acc, (c, d)| acc + &c * &d,
    //     );
    //     let p_vanishing = p_inner_product - &p_result - &p_carry * &p_modulus;
    //     assert_eq!(p_vanishing.degree(), P::NB_WITNESS_LIMBS);

    //     let p_witness = compute_root_quotient_and_shift(
    //         &p_vanishing,
    //         P::WITNESS_OFFSET,
    //         P::NB_BITS_PER_LIMB as u32,
    //     );
    //     let (p_witness_low, p_witness_high) = split_u16_limbs_to_u8_limbs(&p_witness);

    //     self.result = convert_polynomial(p_result);
    //     self.carry = convert_polynomial(p_carry);
    //     self.witness_low = convert_vec(p_witness_low).try_into().unwrap();
    //     self.witness_high = convert_vec(p_witness_high).try_into().unwrap();

    //     result.clone()
    // }

    #[allow(unused_variables)]
    pub fn eval<AB: CurtaAirBuilder<F = F>, P: FieldParameters>(
        builder: &mut AB,
        cols: &EdAddCols<AB::Var>,
        p: &AffinePoint<AB::Var>,
        q: &AffinePoint<AB::Var>,
    ) {
        let x1 = p.x;
        let x2 = q.x;
        let y1 = p.y;
        let y2 = q.y;

        // x3_numerator = x1 * y2 + x2 * y1.
        cols.x3_numerator
            .eval::<AB, P>(builder, &vec![x1, x2], &vec![y2, y1]);

        // y3_numerator = y1 * y2 + x1 * x2.
        cols.y3_numerator
            .eval::<AB, P>(builder, &vec![y1, x1], &vec![y2, x2]);

        // TODO: fill in below

        // // f = x1 * x2 * y1 * y2.
        // let x1_mul_y1 = self.fp_mul(&x1, &y1);
        // let x2_mul_y2 = self.fp_mul(&x2, &y2);
        // let f = self.fp_mul(&x1_mul_y1, &x2_mul_y2);

        // // d * f.
        // let d_mul_f = self.fp_mul_const(&f, E::D);

        // // x3 = x3_numerator / (1 + d * f).
        // let x3_ins = self.fp_den(&x3_numerator, &d_mul_f, true);

        // // y3 = y3_numerator / (1 - d * f).
        // let y3_ins = self.fp_den(&y3_numerator, &d_mul_f, false);
    }
}
