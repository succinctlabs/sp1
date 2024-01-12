use num::{BigUint, Zero};

use crate::air::polynomial::Polynomial;
use p3_field::{Field, PrimeField32, PrimeField64};

// use crate::math::prelude::*;

pub fn bigint_into_u16_digits(x: &BigUint, num_digits: usize) -> Vec<u16> {
    let mut x_limbs = x
        .iter_u32_digits()
        .flat_map(|x| vec![x as u16, (x >> 16) as u16])
        .collect::<Vec<_>>();
    assert!(
        x_limbs.len() <= num_digits,
        "Number too large to fit in {num_digits} digits"
    );
    x_limbs.resize(num_digits, 0);
    x_limbs
}

pub fn biguint_to_16_digits_field<F: Field>(x: &BigUint, num_digits: usize) -> Vec<F> {
    bigint_into_u16_digits(x, num_digits)
        .iter()
        .map(|xi| F::from_canonical_u16(*xi))
        .collect()
}

pub fn digits_to_biguint(digits: &[u16]) -> BigUint {
    let mut x = BigUint::zero();
    for (i, &digit) in digits.iter().enumerate() {
        x += BigUint::from(digit) << (16 * i);
    }
    x
}

#[allow(dead_code)]
pub fn field_limbs_to_biguint<F: PrimeField64>(limbs: &[F]) -> BigUint {
    let mut x = BigUint::zero();
    let digits = limbs.iter().map(|x| x.as_canonical_u64());
    for (i, digit) in digits.enumerate() {
        x += BigUint::from(digit) << (16 * i);
    }
    x
}

#[inline]
pub fn split_u32_limbs_to_u16_limbs<F: PrimeField64>(slice: &[F]) -> (Vec<F>, Vec<F>) {
    (
        slice
            .iter()
            .map(|x| x.as_canonical_u64() as u16)
            .map(|x| F::from_canonical_u16(x))
            .collect(),
        slice
            .iter()
            .map(|x| (x.as_canonical_u64() >> 16) as u16)
            .map(|x| F::from_canonical_u16(x))
            .collect(),
    )
}

fn from_noncanonical_biguint<F: PrimeField64>(num: BigUint) -> F {
    let order = BigUint::from(F::ORDER_U64);
    let reduced = num % order;
    let reduced_u64 = reduced.to_u64_digits()[0];
    F::from_canonical_u64(reduced_u64)
}

#[inline]
pub fn compute_root_quotient_and_shift<F: PrimeField64>(
    p_vanishing: &Polynomial<F>,
    offset: usize,
) -> Vec<F> {
    // Evaluate the vanishing polynomial at x = 2^16.
    let p_vanishing_eval = p_vanishing
        .coefficients()
        .iter()
        .enumerate()
        .map(|(i, x)| from_noncanonical_biguint::<F>(BigUint::from(2u32).pow(16 * i as u32)) * *x)
        .sum::<F>();
    debug_assert_eq!(p_vanishing_eval, F::zero());

    // Compute the witness polynomial by witness(x) = vanishing(x) / (x - 2^16).
    let root_monomial = F::from_canonical_u32(2u32.pow(16));
    let p_quotient = p_vanishing.root_quotient(root_monomial);
    debug_assert_eq!(p_quotient.degree(), p_vanishing.degree() - 1);

    // Sanity Check #1: For all i, |w_i| < 2^20 to prevent overflows.
    let offset_u64 = offset as u64;
    for c in p_quotient.coefficients().iter() {
        debug_assert!(c.neg().as_canonical_u64() < offset_u64 || c.as_canonical_u64() < offset_u64);
    }

    // Sanity Check #2: w(x) * (x - 2^16) = vanishing(x).
    let x_minus_root = Polynomial::<F>::from_coefficients_slice(&[-root_monomial, F::one()]);
    debug_assert_eq!(
        (&p_quotient * &x_minus_root).coefficients(),
        p_vanishing.coefficients()
    );

    // Shifting the witness polynomial to make it positive
    p_quotient
        .coefficients()
        .iter()
        .map(|x| *x + F::from_canonical_u64(offset_u64))
        .collect::<Vec<F>>()
}

#[inline]
pub fn to_field_iter<F: PrimeField32>(
    polynomial: &Polynomial<i64>,
) -> impl Iterator<Item = F> + '_ {
    polynomial
        .coefficients()
        .iter()
        .map(|x| F::from_canonical_u32(*x as u32))
}

pub fn biguint_to_bits_le(integer: &BigUint, num_bits: usize) -> Vec<bool> {
    let byte_vec = integer.to_bytes_le();
    let mut bits = Vec::new();
    for byte in byte_vec {
        for i in 0..8 {
            bits.push(byte & (1 << i) != 0);
        }
    }
    debug_assert!(
        bits.len() <= num_bits,
        "Number too large to fit in {num_bits} digits"
    );
    bits.resize(num_bits, false);
    bits
}

#[cfg(test)]
mod tests {
    use num::bigint::RandBigInt;
    use rand::thread_rng;

    use super::*;

    #[test]
    fn test_bigint_into_u16_digits() {
        let x = BigUint::from(0x1234567890abcdefu64);
        let x_limbs = bigint_into_u16_digits(&x, 4);
        assert_eq!(x_limbs, vec![0xcdef, 0x90ab, 0x5678, 0x1234]);

        let mut rng = thread_rng();
        for _ in 0..100 {
            let x = rng.gen_biguint(256);
            let x_limbs = bigint_into_u16_digits(&x, 16);

            let x_out = digits_to_biguint(&x_limbs);

            assert_eq!(x, x_out)
        }
    }

    #[test]
    fn test_into_bits_le() {
        let mut rng = thread_rng();
        for _ in 0..100 {
            let x = rng.gen_biguint(256);
            let bits = biguint_to_bits_le(&x, 256);
            let mut x_out = BigUint::from(0u32);
            for (i, bit) in bits.iter().enumerate() {
                if *bit {
                    x_out += BigUint::from(1u32) << i;
                }
            }
            assert_eq!(x, x_out);
        }
    }
}
