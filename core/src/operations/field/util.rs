use num::BigUint;
use p3_field::PrimeField32;

use crate::air::Polynomial;

fn biguint_to_field<F: PrimeField32>(num: BigUint) -> F {
    let mut x = F::zero();
    let mut power = F::from_canonical_u32(1u32);
    let base = F::from_canonical_u64((1 << 32) % F::ORDER_U64);
    let digits = num.iter_u32_digits();
    for digit in digits.into_iter() {
        x += F::from_canonical_u32(digit) * power;
        power *= base;
    }
    x
}

#[inline]
pub fn compute_root_quotient_and_shift<F: PrimeField32>(
    p_vanishing: &Polynomial<F>,
    offset: usize,
    nb_bits_per_limb: u32,
    nb_limbs: usize,
) -> Vec<F> {
    // Evaluate the vanishing polynomial at x = 2^nb_bits_per_limb.

    let p_vanishing_eval = p_vanishing
        .coefficients()
        .iter()
        .enumerate()
        .map(|(i, x)| {
            biguint_to_field::<F>(BigUint::from(2u32) << (nb_bits_per_limb * i as u32)) * *x
        })
        .sum::<F>();
    debug_assert_eq!(p_vanishing_eval, F::zero());

    // Compute the witness polynomial by witness(x) = vanishing(x) / (x - 2^nb_bits_per_limb).
    let root_monomial = F::from_canonical_u32(2u32.pow(nb_bits_per_limb));
    let p_quotient = p_vanishing.root_quotient(root_monomial);
    debug_assert_eq!(p_quotient.degree(), p_vanishing.degree() - 1);

    // Sanity Check #1: For all i, |w_i| < 2^20 to prevent overflows.
    let offset_u64 = offset as u64;
    for c in p_quotient.coefficients().iter() {
        debug_assert!(c.neg().as_canonical_u64() < offset_u64 || c.as_canonical_u64() < offset_u64);
    }

    // Sanity Check #2: w(x) * (x - 2^nb_bits_per_limb) = vanishing(x).
    let x_minus_root = Polynomial::<F>::from_coefficients(&[-root_monomial, F::one()]);
    debug_assert_eq!((&p_quotient * &x_minus_root), *p_vanishing);

    let mut p_quotient_coefficients = p_quotient.as_coefficients();
    p_quotient_coefficients.resize(nb_limbs, F::zero());

    // Shifting the witness polynomial to make it positive
    p_quotient_coefficients
        .into_iter()
        .map(|x| x + F::from_canonical_u64(offset_u64))
        .collect::<Vec<F>>()
}

#[inline]
pub fn split_u16_limbs_to_u8_limbs<F: PrimeField32>(slice: &[F]) -> (Vec<F>, Vec<F>) {
    (
        slice
            .iter()
            .map(|x| x.as_canonical_u64() as u8)
            .map(|x| F::from_canonical_u8(x))
            .collect(),
        slice
            .iter()
            .map(|x| (x.as_canonical_u64() >> 8) as u8)
            .map(|x| F::from_canonical_u8(x))
            .collect(),
    )
}
