use crate::{syscall_ed_add, utils::AffinePoint};

/// The number of limbs in [Ed25519AffinePoint].
pub const N: usize = 8;

/// An affine point on the Ed25519 curve.
#[derive(Copy, Clone)]
#[repr(align(8))]
pub struct Ed25519AffinePoint(pub [u64; N]);

impl AffinePoint<N> for Ed25519AffinePoint {
    /// The generator/base point for the Ed25519 curve. Reference: https://datatracker.ietf.org/doc/html/rfc7748#section-4.1
    const GENERATOR: [u64; N] = [
        0xc9562d608f25d51a,
        0x692cc7609525a7b2,
        0xc0a4e231fdd6dc5c,
        0x216936d3cd6e53fe,
        0x6666666666666658,
        0x6666666666666666,
        0x6666666666666666,
        0x6666666666666666,
    ];

    #[allow(deprecated)]
    const GENERATOR_T: Self = Self(Self::GENERATOR);

    fn new(limbs: [u64; N]) -> Self {
        Self(limbs)
    }

    fn identity() -> Self {
        Self::identity()
    }

    fn limbs_ref(&self) -> &[u64; N] {
        &self.0
    }

    fn limbs_mut(&mut self) -> &mut [u64; N] {
        &mut self.0
    }

    fn add_assign(&mut self, other: &Self) {
        let a = self.limbs_mut();
        let b = other.limbs_ref();
        unsafe {
            syscall_ed_add(a, b);
        }
    }

    fn is_identity(&self) -> bool {
        self.0 == Self::IDENTITY
    }

    /// In Edwards curves, doubling is the same as adding a point to itself.
    fn double(&mut self) {
        let a = self.limbs_mut();
        unsafe {
            syscall_ed_add(a, a);
        }
    }
}

impl Ed25519AffinePoint {
    const IDENTITY: [u64; N] = [0, 0, 0, 0, 1, 0, 0, 0];

    pub fn identity() -> Self {
        Self(Self::IDENTITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    #[test]
    fn generator_matches_rfc7748() {
        // RFC 7748 section 4.1 gives these affine coordinates in decimal.
        let expected_x = BigUint::parse_bytes(
            b"15112221349535400772501151409588531511454012693041857206046113283949847762202",
            10,
        )
        .unwrap();
        let expected_y = BigUint::parse_bytes(
            b"46316835694926478169428394003475163141307993866256225615783033603165251855960",
            10,
        )
        .unwrap();
        let bytes = Ed25519AffinePoint::GENERATOR_T.to_le_bytes();
        let x = BigUint::from_bytes_le(&bytes[..32]);
        let y = BigUint::from_bytes_le(&bytes[32..]);
        assert_eq!(x, expected_x);
        assert_eq!(y, expected_y);

        // Check canonical coordinates and -x^2 + y^2 = 1 + d*x^2*y^2 (mod p).
        let p = (BigUint::from(1u8) << 255usize) - BigUint::from(19u8);
        let d = BigUint::parse_bytes(
            b"37095705934669439343138083508754565189542113879843219016388785533085940283555",
            10,
        )
        .unwrap();
        assert!(x < p && y < p);
        let x2 = &x * &x % &p;
        let y2 = &y * &y % &p;
        assert_eq!(y2, (BigUint::from(1u8) + &x2 + d * &x2 * &y2) % &p);
    }
}
