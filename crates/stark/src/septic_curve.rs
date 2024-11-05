//! Elliptic Curve `y^2 = x^3 + 2x + 26z^5` over the `F_{p^7} = F_p[z]/(z^7 - 2z - 5)` extension field.

use crate::septic_extension::SepticExtension;
use p3_field::{AbstractExtensionField, AbstractField, Field, PrimeField32};
use serde::{Deserialize, Serialize};
/// A septic elliptic curve point on y^2 = x^3 + 2x + 26z^5 over field `F_{p^7} = F_p[z]/(z^7 - 2z - 5)`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SepticCurve<F> {
    x: SepticExtension<F>,
    y: SepticExtension<F>,
}

impl<F: Field> SepticCurve<F> {
    /// Returns the x-coordinate of the curve point.
    pub fn get_x(&self) -> SepticExtension<F> {
        self.x
    }

    /// Returns the y-coordinate of the curve point
    pub fn get_y(&self) -> SepticExtension<F> {
        self.y
    }

    /// Evaluates the curve formula x^3 + 2x + 26z^5
    pub fn curve_formula(x: SepticExtension<F>) -> SepticExtension<F> {
        x.cube()
            + x * F::two()
            + SepticExtension::from_base_slice(&[
                F::zero(),
                F::zero(),
                F::zero(),
                F::zero(),
                F::zero(),
                F::from_canonical_u32(26),
                F::zero(),
            ])
    }

    /// Check if a `SepticCurve` struct is on the elliptic curve.
    pub fn check_on_point(&self) -> bool {
        self.y.square() == Self::curve_formula(self.x)
    }

    #[must_use]
    /// Adds two elliptic curve points, assuming that the addition doesn't lead to the exception cases of weierstrass addition.
    pub fn add_incomplete(&self, other: SepticCurve<F>) -> Self {
        let slope = (other.y - self.y) / (other.x - self.x);
        let result_x = slope.square() - self.x - other.x;
        let result_y = slope * (self.x - result_x) - self.y;
        Self { x: result_x, y: result_y }
    }
}

impl<F: PrimeField32> SepticCurve<F> {
    /// Lift an x coordinate into an elliptic curve.
    /// As an x-coordinate may not be a valid one, we allow additions of [0, 256) * 2^16 to the first entry of the x-coordinate.
    /// Also, we always return the curve point with y-coordinate within [0, (p-1)/2), where p is the characteristic.
    /// The returned values are the curve point and the offset used.
    pub fn lift_x(x: SepticExtension<F>) -> (Self, u8) {
        for offset in 0..=255 {
            let x_trial =
                x + SepticExtension::from_base(F::from_canonical_u32((offset as u32) << 16));
            let y_sq = Self::curve_formula(x_trial);
            if y_sq.is_square() {
                let mut y = y_sq.sqrt().unwrap();
                if y.is_exception() {
                    continue;
                }
                if y.is_send() {
                    y = -y;
                }
                return (Self { x: x_trial, y }, offset);
            }
        }
        panic!("curve point couldn't be found after 256 attempts");
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;

    use super::*;

    #[test]
    fn test_lift_x() {
        let x: SepticExtension<BabyBear> = SepticExtension::from_base_slice(&[
            BabyBear::from_canonical_u32(0x2013),
            BabyBear::from_canonical_u32(0x2015),
            BabyBear::from_canonical_u32(0x2016),
            BabyBear::from_canonical_u32(0x2023),
            BabyBear::from_canonical_u32(0x2024),
            BabyBear::from_canonical_u32(0x2016),
            BabyBear::from_canonical_u32(0x2017),
        ]);
        let (curve_point, _) = SepticCurve::<BabyBear>::lift_x(x);
        assert!(curve_point.check_on_point());
        assert!(curve_point.x.is_receive());
    }
}
