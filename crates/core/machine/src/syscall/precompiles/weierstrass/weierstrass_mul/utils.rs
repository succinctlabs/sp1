//! Tracegen-only helpers for the Weierstrass scalar-multiplication chips.
//!
//! These compute the affine result of an add or double under the same
//! assumptions made by the `weierstrass_add` / `weierstrass_double` chips and
//! return the answer in the same `Limbs<F, ...>` form used by the controller's
//! columns. No field-op witness columns are populated — the controller uses
//! these to enumerate the (input, output) pairs it forwards to the internal
//! add/double chips during tracegen.

use generic_array::ArrayLength;
use num::BigUint;
use slop_algebra::PrimeField32;
use sp1_curves::{
    params::{FieldParameters, Limbs, NumLimbs},
    weierstrass::WeierstrassParameters,
    EllipticCurve,
};

fn limbs_to_biguint<F: PrimeField32, N: ArrayLength>(limbs: &Limbs<F, N>) -> BigUint {
    let bytes: Vec<u8> = limbs.0.iter().map(|f| f.as_canonical_u32() as u8).collect();
    BigUint::from_bytes_le(&bytes)
}

/// Convert an iterator of little-endian `u64` words representing one
/// field-element coordinate into the byte-per-limb `Limbs<F, N>` form used in
/// the chips' columns. Accepts both `&[u64]` (via `.iter().copied()`) and
/// memory-record iterators (via `.iter().map(|r| r.value)`).
pub fn event_words_to_limbs<F: PrimeField32, N: ArrayLength>(
    words: impl IntoIterator<Item = u64>,
) -> Limbs<F, N> {
    words.into_iter().flat_map(|w| w.to_le_bytes()).map(F::from_canonical_u8).collect()
}

/// Convert an iterator of little-endian `u64` words representing one
/// field-element coordinate into a `BigUint`, suitable for feeding into a
/// chip's `populate_field_ops`.
fn event_words_to_biguint(words: impl IntoIterator<Item = u64>) -> BigUint {
    let bytes: Vec<u8> = words.into_iter().flat_map(|w| w.to_le_bytes()).collect();
    BigUint::from_bytes_le(&bytes)
}

/// Inverse of [`event_words_to_limbs`]: pack a `Limbs<F, N>` into a `Vec<u64>` of
/// little-endian words. Each limb must be a byte stored as a field element (this
/// is the invariant maintained by the chips' column populations).
fn limbs_to_event_words<F: PrimeField32, N: ArrayLength>(limbs: &Limbs<F, N>) -> Vec<u64> {
    limbs
        .0
        .chunks(8)
        .map(|chunk| {
            let mut bytes = [0u8; 8];
            for (i, f) in chunk.iter().enumerate() {
                bytes[i] = f.as_canonical_u32() as u8;
            }
            u64::from_le_bytes(bytes)
        })
        .collect()
}

/// Split a `&[u64]` representing the concatenation of two coordinates `(x, y)`
/// (the layout used by `EllipticCurveMulEvent::p` and the internal add/double
/// channel events) into two `Limbs<F, N>`.
pub fn event_words_to_point_limbs<F: PrimeField32, N: ArrayLength>(
    words: &[u64],
) -> (Limbs<F, N>, Limbs<F, N>) {
    let half = words.len() / 2;
    (
        event_words_to_limbs(words[..half].iter().copied()),
        event_words_to_limbs(words[half..].iter().copied()),
    )
}

/// `BigUint` counterpart of [`event_words_to_point_limbs`].
pub fn event_words_to_point_biguint(words: &[u64]) -> (BigUint, BigUint) {
    let half = words.len() / 2;
    (
        event_words_to_biguint(words[..half].iter().copied()),
        event_words_to_biguint(words[half..].iter().copied()),
    )
}

/// Inverse of [`event_words_to_point_limbs`]: pack two `Limbs<F, N>` (x, y) into
/// a single `Vec<u64>` in the channel-event coordinate-pair layout.
pub fn point_limbs_to_event_words<F: PrimeField32, N: ArrayLength>(
    x: &Limbs<F, N>,
    y: &Limbs<F, N>,
) -> Vec<u64> {
    let mut words = limbs_to_event_words(x);
    words.extend(limbs_to_event_words(y));
    words
}

/// Affine elliptic-curve addition under the same assumptions as the
/// `weierstrass_add` chip: both inputs are non-identity, `p != q`, and
/// `p_x != q_x` mod the base-field modulus (so the slope denominator is
/// invertible).
pub fn affine_add<F: PrimeField32, E: EllipticCurve + WeierstrassParameters>(
    p_x: &Limbs<F, <E::BaseField as NumLimbs>::Limbs>,
    p_y: &Limbs<F, <E::BaseField as NumLimbs>::Limbs>,
    q_x: &Limbs<F, <E::BaseField as NumLimbs>::Limbs>,
    q_y: &Limbs<F, <E::BaseField as NumLimbs>::Limbs>,
) -> (Limbs<F, <E::BaseField as NumLimbs>::Limbs>, Limbs<F, <E::BaseField as NumLimbs>::Limbs>) {
    let modulus = E::BaseField::modulus();

    let p_x = limbs_to_biguint(p_x);
    let p_y = limbs_to_biguint(p_y);
    let q_x = limbs_to_biguint(q_x);
    let q_y = limbs_to_biguint(q_y);

    // slope = (q_y - p_y) / (q_x - p_x)
    let num = (&q_y + &modulus - &p_y) % &modulus;
    let den = (&q_x + &modulus - &p_x) % &modulus;
    let den_inv = den.modpow(&(&modulus - 2u32), &modulus);
    let slope = (&num * &den_inv) % &modulus;

    // x3 = slope^2 - p_x - q_x
    let slope_sq = (&slope * &slope) % &modulus;
    let two_mod = &modulus + &modulus;
    let x3 = (&slope_sq + &two_mod - &p_x - &q_x) % &modulus;

    // y3 = slope * (p_x - x3) - p_y
    let p_x_minus_x3 = (&p_x + &modulus - &x3) % &modulus;
    let y3 = (&slope * &p_x_minus_x3 + &modulus - &p_y) % &modulus;

    (E::BaseField::to_limbs_field::<F, F>(&x3), E::BaseField::to_limbs_field::<F, F>(&y3))
}

/// Affine elliptic-curve doubling under the same assumptions as the
/// `weierstrass_double` chip: `p` is non-identity and `p_y != 0` mod the
/// base-field modulus (so the slope denominator is invertible).
pub fn affine_double<F: PrimeField32, E: EllipticCurve + WeierstrassParameters>(
    p_x: &Limbs<F, <E::BaseField as NumLimbs>::Limbs>,
    p_y: &Limbs<F, <E::BaseField as NumLimbs>::Limbs>,
) -> (Limbs<F, <E::BaseField as NumLimbs>::Limbs>, Limbs<F, <E::BaseField as NumLimbs>::Limbs>) {
    let modulus = E::BaseField::modulus();
    let a = E::a_int();

    let p_x = limbs_to_biguint(p_x);
    let p_y = limbs_to_biguint(p_y);

    // slope = (a + 3 * p_x^2) / (2 * p_y)
    let p_x_sq = (&p_x * &p_x) % &modulus;
    let three_p_x_sq = (BigUint::from(3u32) * &p_x_sq) % &modulus;
    let num = (&a + &three_p_x_sq) % &modulus;
    let den = (BigUint::from(2u32) * &p_y) % &modulus;
    let den_inv = den.modpow(&(&modulus - 2u32), &modulus);
    let slope = (&num * &den_inv) % &modulus;

    // x3 = slope^2 - 2 * p_x
    let slope_sq = (&slope * &slope) % &modulus;
    let two_p_x = (BigUint::from(2u32) * &p_x) % &modulus;
    let two_mod = &modulus + &modulus;
    let x3 = (&slope_sq + &two_mod - &two_p_x) % &modulus;

    // y3 = slope * (p_x - x3) - p_y
    let p_x_minus_x3 = (&p_x + &modulus - &x3) % &modulus;
    let y3 = (&slope * &p_x_minus_x3 + &modulus - &p_y) % &modulus;

    (E::BaseField::to_limbs_field::<F, F>(&x3), E::BaseField::to_limbs_field::<F, F>(&y3))
}
