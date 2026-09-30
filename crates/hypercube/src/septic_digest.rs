//! Elliptic Curve digests with a starting point to avoid weierstrass addition exceptions.
use crate::{septic_curve::SepticCurve, septic_extension::SepticExtension};
use deepsize2::DeepSizeOf;
use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractExtensionField, AbstractField, Field};
use std::{iter::Sum, ops::Add};

/// The x-coordinate for a curve point used as a starting cumulative sum for global permutation
/// trace generation, derived from `sqrt(2)`.
pub const CURVE_CUMULATIVE_SUM_START_X: [u32; 7] =
    [0x1414213, 0x5623730, 0x9504880, 0x1688724, 0x2096980, 0x7856967, 0x1875376];

/// The y-coordinate for a curve point used as a starting cumulative sum for global permutation
/// trace generation, derived from `sqrt(2)`.
pub const CURVE_CUMULATIVE_SUM_START_Y: [u32; 7] =
    [2020310104, 1513506566, 1843922297, 2003644209, 805967281, 1882435203, 1623804682];

/// The x-coordinate for a curve point used as a starting random point for digest accumulation,
/// derived from `sqrt(3)`.
pub const DIGEST_SUM_START_X: [u32; 7] =
    [0x1732050, 0x8075688, 0x7729352, 0x7446341, 0x5058723, 0x6694280, 0x5253810];

/// The y-coordinate for a curve point used as a starting random point for digest accumulation,
/// derived from `sqrt(3)`.
pub const DIGEST_SUM_START_Y: [u32; 7] =
    [1095433104, 7540207, 1124564165, 2035506693, 11121645, 102781365, 398772161];

/// A global cumulative sum digest, a point on the elliptic curve that `SepticCurve<F>` represents.
/// As these digests start with the `CURVE_CUMULATIVE_SUM_START` point, they require special summing
/// logic.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash, DeepSizeOf)]
#[repr(C)]
pub struct SepticDigest<F>(pub SepticCurve<F>);

impl<F: AbstractField> SepticDigest<F> {
    #[must_use]
    /// The zero digest, the starting point of the accumulation of curve points derived from the
    /// scheme.
    pub fn zero() -> Self {
        SepticDigest(SepticCurve {
            x: SepticExtension::<F>::from_base_fn(|i| {
                F::from_canonical_u32(CURVE_CUMULATIVE_SUM_START_X[i])
            }),
            y: SepticExtension::<F>::from_base_fn(|i| {
                F::from_canonical_u32(CURVE_CUMULATIVE_SUM_START_Y[i])
            }),
        })
    }

    #[must_use]
    /// The digest used for starting the accumulation of digests.
    pub fn starting_digest() -> Self {
        SepticDigest(SepticCurve {
            x: SepticExtension::<F>::from_base_fn(|i| F::from_canonical_u32(DIGEST_SUM_START_X[i])),
            y: SepticExtension::<F>::from_base_fn(|i| F::from_canonical_u32(DIGEST_SUM_START_Y[i])),
        })
    }
}

impl<F: Field> SepticDigest<F> {
    /// Checks that the digest is zero, the starting point of the accumulation.
    pub fn is_zero(&self) -> bool {
        *self == SepticDigest::<F>::zero()
    }

    /// Adds two digests, returning `None` if an incomplete curve addition is exceptional.
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        fn checked_add_incomplete<F: Field>(
            lhs: SepticCurve<F>,
            rhs: SepticCurve<F>,
        ) -> Option<SepticCurve<F>> {
            if lhs.x == rhs.x {
                return None;
            }
            Some(lhs.add_incomplete(rhs))
        }

        let start = Self::starting_digest().0;
        let zero = Self::zero().0;

        let sum_a = checked_add_incomplete(start, self.0)?;
        let sum_a = checked_add_incomplete(sum_a, zero.neg())?;
        let sum_b = checked_add_incomplete(sum_a, rhs.0)?;
        let sum_b = checked_add_incomplete(sum_b, zero.neg())?;
        let result = checked_add_incomplete(sum_b, zero)?;
        let result = checked_add_incomplete(result, start.neg())?;

        Some(SepticDigest(result))
    }
}

impl<F: Field> Add for SepticDigest<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        let start = Self::starting_digest().0;

        let sum_a = start.add_incomplete(self.0).sub_incomplete(Self::zero().0);
        let sum_b = sum_a.add_incomplete(rhs.0).sub_incomplete(Self::zero().0);

        let mut result = sum_b;
        result.add_assign(SepticDigest::<F>::zero().0);
        result.sub_assign(start);

        SepticDigest(result)
    }
}

impl<F: Field> Sum for SepticDigest<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let start = SepticDigest::<F>::starting_digest().0;

        // Computation order is start + (digest1 - offset) + (digest2 - offset) + ... + (digestN -
        // offset) + offset - start.
        let mut ret = iter.fold(start, |acc, x| {
            let sum_offset = acc.add_incomplete(x.0);
            sum_offset.sub_incomplete(SepticDigest::<F>::zero().0)
        });

        ret.add_assign(SepticDigest::<F>::zero().0);
        ret.sub_assign(start);
        SepticDigest(ret)
    }
}

#[cfg(test)]
mod test {
    use crate::septic_curve::{CURVE_WITNESS_DUMMY_POINT_X, CURVE_WITNESS_DUMMY_POINT_Y};

    use super::*;

    use sp1_primitives::SP1Field;
    #[test]
    fn test_const_points() {
        let x: SepticExtension<SP1Field> = SepticExtension::from_base_fn(|i| {
            SP1Field::from_canonical_u32(CURVE_CUMULATIVE_SUM_START_X[i])
        });
        let y: SepticExtension<SP1Field> = SepticExtension::from_base_fn(|i| {
            SP1Field::from_canonical_u32(CURVE_CUMULATIVE_SUM_START_Y[i])
        });
        let point = SepticCurve { x, y };
        assert!(point.check_on_point());
        let x: SepticExtension<SP1Field> =
            SepticExtension::from_base_fn(|i| SP1Field::from_canonical_u32(DIGEST_SUM_START_X[i]));
        let y: SepticExtension<SP1Field> =
            SepticExtension::from_base_fn(|i| SP1Field::from_canonical_u32(DIGEST_SUM_START_Y[i]));
        let point = SepticCurve { x, y };
        assert!(point.check_on_point());
        let x: SepticExtension<SP1Field> = SepticExtension::from_base_fn(|i| {
            SP1Field::from_canonical_u32(CURVE_WITNESS_DUMMY_POINT_X[i])
        });
        let y: SepticExtension<SP1Field> = SepticExtension::from_base_fn(|i| {
            SP1Field::from_canonical_u32(CURVE_WITNESS_DUMMY_POINT_Y[i])
        });
        let point = SepticCurve { x, y };
        assert!(point.check_on_point());
    }

    #[test]
    fn test_checked_add_rejects_exceptional_intermediate() {
        let lhs = SepticDigest::<SP1Field>::zero();
        let intermediate = SepticDigest::<SP1Field>::starting_digest()
            .0
            .add_incomplete(lhs.0)
            .sub_incomplete(SepticDigest::zero().0);

        // This is a valid curve point, but adding it next would use equal x-coordinates and divide
        // by zero in the incomplete addition formula.
        assert!(intermediate.check_on_point());
        assert_eq!(lhs.checked_add(SepticDigest(intermediate)), None);
    }

    #[test]
    fn test_checked_add_matches_add() {
        let lhs = SepticDigest::<SP1Field>::zero();
        let rhs = SepticDigest::<SP1Field>::zero();

        assert_eq!(lhs.checked_add(rhs), Some(lhs + rhs));
    }
}
