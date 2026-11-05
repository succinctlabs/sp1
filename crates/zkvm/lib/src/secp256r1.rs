use crate::{
    syscall_secp256r1_add, syscall_secp256r1_double,
    utils::{AffinePoint, WeierstrassAffinePoint, WeierstrassPoint},
};

/// The number of limbs in [Secp256r1Point].
pub const N: usize = 8;

/// An affine point on the Secp256r1 curve.
#[derive(Copy, Clone, Debug)]
#[repr(align(8))]
pub struct Secp256r1Point(pub WeierstrassPoint<N>);

impl WeierstrassAffinePoint<N> for Secp256r1Point {
    fn infinity() -> Self {
        Self(WeierstrassPoint::Infinity)
    }

    fn is_infinity(&self) -> bool {
        matches!(self.0, WeierstrassPoint::Infinity)
    }
}

impl AffinePoint<N> for Secp256r1Point {
    const DECOMPACT_WITH_MIN_Y: bool = true;

    const GENERATOR: [u64; N] = [
        17627433388654248598,
        8575836109218198432,
        17923454489921339634,
        7716867327612699207,
        14678990851816772085,
        3156516839386865358,
        10297457778147434006,
        5756518291402817435,
    ];

    #[allow(deprecated)]
    const GENERATOR_T: Self = Self(WeierstrassPoint::Affine(Self::GENERATOR));

    fn new(limbs: [u64; N]) -> Self {
        Self(WeierstrassPoint::Affine(limbs))
    }

    fn identity() -> Self {
        Self::infinity()
    }

    fn is_identity(&self) -> bool {
        self.is_infinity()
    }

    fn limbs_ref(&self) -> &[u64; N] {
        match &self.0 {
            WeierstrassPoint::Infinity => panic!("Infinity point has no limbs"),
            WeierstrassPoint::Affine(limbs) => limbs,
        }
    }

    fn limbs_mut(&mut self) -> &mut [u64; N] {
        match &mut self.0 {
            WeierstrassPoint::Infinity => panic!("Infinity point has no limbs"),
            WeierstrassPoint::Affine(limbs) => limbs,
        }
    }

    fn add_assign(&mut self, other: &Self) {
        let a = self.limbs_mut();
        let b = other.limbs_ref();
        unsafe {
            syscall_secp256r1_add(a, b);
        }
    }

    fn complete_add_assign(&mut self, other: &Self) {
        self.weierstrass_add_assign(other);
    }

    fn double(&mut self) {
        match &mut self.0 {
            WeierstrassPoint::Infinity => (),
            WeierstrassPoint::Affine(limbs) => unsafe {
                syscall_secp256r1_double(limbs);
            },
        }
    }
}
