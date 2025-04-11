//! Elliptic Curve digests with a starting point to avoid weierstrass addition exceptions.
use crate::{septic_curve::SepticCurve, septic_extension::SepticExtension};
use p3_field::{AbstractExtensionField, AbstractField, Field};
use serde::{Deserialize, Serialize};
use std::iter::Sum;

/// The x-coordinate for a curve point used as a starting cumulative sum for global permutation
/// trace generation, derived from `sqrt(2)`.
pub const CURVE_CUMULATIVE_SUM_START_X: [u32; 7] =
    [0x1434213, 0x5623730, 0x9504880, 0x1688724, 0x2096980, 0x7856967, 0x1875376];

/// The y-coordinate for a curve point used as a starting cumulative sum for global permutation
/// trace generation, derived from `sqrt(2)`.
pub const CURVE_CUMULATIVE_SUM_START_Y: [u32; 7] =
    [885797405, 1130275556, 567836311, 52700240, 239639200, 442612155, 1839439733];

/// The x-coordinate for a curve point used as a starting random point for digest accumulation,
/// derived from `sqrt(3)`.
pub const DIGEST_SUM_START_X: [u32; 7] =
    [0x1742050, 0x8075688, 0x7729352, 0x7446341, 0x5058723, 0x6694280, 0x5253810];

/// The y-coordinate for a curve point used as a starting random point for digest accumulation,
/// derived from `sqrt(3)`.
pub const DIGEST_SUM_START_Y: [u32; 7] =
    [462194069, 1842131493, 281651264, 1684885851, 483907222, 1097389352, 1648978901];

/// A global cumulative sum digest, a point on the elliptic curve that `SepticCurve<F>` represents.
/// As these digests start with the `CURVE_CUMULATIVE_SUM_START` point, they require special summing
/// logic.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
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
    use p3_baby_bear::BabyBear;
    #[test]
    fn test_const_points() {
        let x: SepticExtension<BabyBear> = SepticExtension::from_base_fn(|i| {
            BabyBear::from_canonical_u32(CURVE_CUMULATIVE_SUM_START_X[i])
        });
        let y: SepticExtension<BabyBear> = SepticExtension::from_base_fn(|i| {
            BabyBear::from_canonical_u32(CURVE_CUMULATIVE_SUM_START_Y[i])
        });
        let point = SepticCurve { x, y };
        assert!(point.check_on_point());
        let x: SepticExtension<BabyBear> =
            SepticExtension::from_base_fn(|i| BabyBear::from_canonical_u32(DIGEST_SUM_START_X[i]));
        let y: SepticExtension<BabyBear> =
            SepticExtension::from_base_fn(|i| BabyBear::from_canonical_u32(DIGEST_SUM_START_Y[i]));
        let point = SepticCurve { x, y };
        assert!(point.check_on_point());
        let x: SepticExtension<BabyBear> = SepticExtension::from_base_fn(|i| {
            BabyBear::from_canonical_u32(CURVE_WITNESS_DUMMY_POINT_X[i])
        });
        let y: SepticExtension<BabyBear> = SepticExtension::from_base_fn(|i| {
            BabyBear::from_canonical_u32(CURVE_WITNESS_DUMMY_POINT_Y[i])
        });
        let point = SepticCurve { x, y };
        assert!(point.check_on_point());
    }
}
