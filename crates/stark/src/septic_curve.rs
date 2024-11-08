//! Elliptic Curve `y^2 = x^3 + 2x + 26z^5` over the `F_{p^7} = F_p[z]/(z^7 - 2z - 5)` extension field.
use crate::septic_extension::SepticExtension;
use p3_field::{AbstractExtensionField, AbstractField, Field, PrimeField32};
use serde::{Deserialize, Serialize};
/// A septic elliptic curve point on y^2 = x^3 + 2x + 26z^5 over field `F_{p^7} = F_p[z]/(z^7 - 2z - 5)`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SepticCurve<F> {
    /// The x-coordinate of an elliptic curve point.
    pub x: SepticExtension<F>,
    /// The y-coordinate of an elliptic curve point.
    pub y: SepticExtension<F>,
}

/// Linear coefficient for pairwise independent hash, derived from digits of pi.
pub const A_EC_LOGUP: [u32; 7] =
    [0x31415926, 0x53589793, 0x23846264, 0x33832795, 0x02884197, 0x16939937, 0x51058209];

/// Constant coefficient for pairwise independent hash, derived from digits of pi.
pub const B_EC_LOGUP: [u32; 7] =
    [0x74944592, 0x30781640, 0x62862089, 0x9862803, 0x48253421, 0x17067982, 0x14808651];

/// The x-coordinate for a curve point used as a witness for padding interactions.
pub const CURVE_WITNESS_DUMMY_POINT_X: [u32; 7] =
    [0x2738281, 0x8284590, 0x4523536, 0x0287471, 0x3526624, 0x9775724, 0x7093699];

/// The y-coordinate for a curve point used as a witness for padding interactions.
pub const CURVE_WITNESS_DUMMY_POINT_Y: [u32; 7] =
    [48041908, 550064556, 415267377, 1726976249, 1253299140, 209439863, 1302309485];

impl<F: Field> SepticCurve<F> {
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

    /// Negates a `SepticCurve` point.
    #[must_use]
    pub fn neg(&self) -> Self {
        SepticCurve { x: self.x, y: -self.y }
    }

    #[must_use]
    /// Adds two elliptic curve points, assuming that the addition doesn't lead to the exception cases of weierstrass addition.
    pub fn add_incomplete(&self, other: SepticCurve<F>) -> Self {
        let slope = (other.y - self.y) / (other.x - self.x);
        let result_x = slope.square() - self.x - other.x;
        let result_y = slope * (self.x - result_x) - self.y;
        Self { x: result_x, y: result_y }
    }

    /// Add assigns an elliptic curve point, assuming that the addition doesn't lead to the exception cases of weierstrass addition.
    pub fn add_assign(&mut self, other: SepticCurve<F>) {
        let result = self.add_incomplete(other);
        self.x = result.x;
        self.y = result.y;
    }

    /// Subtracts two elliptic curve points, assuming that the subtraction doesn't lead to the exception cases of weierstrass addition.
    #[must_use]
    pub fn sub_incomplete(&self, other: SepticCurve<F>) -> Self {
        self.add_incomplete(other.neg())
    }

    /// Subtract assigns an elliptic curve point, assuming that the subtraction doesn't lead to the exception cases of weierstrass addition.
    pub fn sub_assign(&mut self, other: SepticCurve<F>) {
        let result = self.add_incomplete(other.neg());
        self.x = result.x;
        self.y = result.y;
    }
}

impl<F: PrimeField32> SepticCurve<F> {
    /// Lift an x coordinate into an elliptic curve.
    /// As an x-coordinate may not be a valid one, we allow additions of [0, 256) * 2^16 to the first entry of the x-coordinate.
    /// Also, we always return the curve point with y-coordinate within [0, (p-1)/2), where p is the characteristic.
    /// The returned values are the curve point and the offset used.
    pub fn lift_x(x: SepticExtension<F>) -> (Self, u8) {
        let a_ec_logup =
            SepticExtension::<F>::from_base_fn(|i| F::from_canonical_u32(A_EC_LOGUP[i]));
        let b_ec_logup =
            SepticExtension::<F>::from_base_fn(|i| F::from_canonical_u32(B_EC_LOGUP[i]));

        for offset in 0..=255 {
            let x_trial =
                x + SepticExtension::from_base(F::from_canonical_u32((offset as u32) << 16));
            let x_trial = a_ec_logup * x_trial + b_ec_logup;
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

impl<F: AbstractField> SepticCurve<F> {
    /// Given three points p1, p2, p3, the function is zero if and only if p3.x == (p1 + p2).x assuming that p1 != p2.
    pub fn sum_checker_x(
        p1: SepticCurve<F>,
        p2: SepticCurve<F>,
        p3: SepticCurve<F>,
    ) -> SepticExtension<F> {
        p3.x * (p2.x.clone() - p1.x.clone()).square() - (p2.y.clone() - p1.y.clone()).square()
            + (p1.x.clone() + p2.x.clone()) * (p2.x - p1.x).square()
    }

    /// Given three points p1, p2, p3, the function is zero if and only if p3.y == (p1 + p2).y assuming that p1 != p2.
    pub fn sum_checker_y(
        p1: SepticCurve<F>,
        p2: SepticCurve<F>,
        p3: SepticCurve<F>,
    ) -> SepticExtension<F> {
        (p1.y.clone() + p3.y.clone()) * (p2.x.clone() - p1.x.clone())
            - (p2.y - p1.y.clone()) * (p1.x - p3.x)
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use std::time::Instant;

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

    #[test]
    #[ignore]
    fn test_simple_bench() {
        const D: u32 = 1 << 16;
        let mut vec = Vec::new();
        let start = Instant::now();
        for i in 0..D {
            let x: SepticExtension<BabyBear> = SepticExtension::from_base_slice(&[
                BabyBear::from_canonical_u32(i + 25),
                BabyBear::from_canonical_u32(2 * i + 376),
                BabyBear::from_canonical_u32(4 * i + 23),
                BabyBear::from_canonical_u32(8 * i + 531),
                BabyBear::from_canonical_u32(16 * i + 542),
                BabyBear::from_canonical_u32(32 * i + 196),
                BabyBear::from_canonical_u32(64 * i + 667),
            ]);
            let (curve_point, _) = SepticCurve::<BabyBear>::lift_x(x);
            vec.push(curve_point);
        }
        println!("Time elapsed: {:?}", start.elapsed());
        let start = Instant::now();
        for i in 0..D {
            let _ = vec[i as usize].add_incomplete(vec[((i + 1) % D) as usize]);
        }
        println!("Time elapsed: {:?}", start.elapsed());
    }
}
