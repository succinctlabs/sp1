use crate::{
    syscall_secp256r1_add, syscall_secp256r1_double,
    utils::{AffinePoint, WeierstrassAffinePoint, WeierstrassPoint},
};

/// The number of limbs in [Secp256r1Point].
pub const N: usize = 16;

/// An affine point on the Secp256k1 curve.
#[derive(Copy, Clone, Debug)]
#[repr(align(4))]
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
    const GENERATOR: [u32; N] = [
        3633889942, 4104206661, 770388896, 1996717441, 1671708914, 4173129445, 3777774151,
        1796723186, 935285237, 3417718888, 1798397646, 734933847, 2081398294, 2397563722,
        4263149467, 1340293858,
    ];

    #[allow(deprecated)]
    const GENERATOR_T: Self = Self(WeierstrassPoint::Affine(Self::GENERATOR));

    fn new(limbs: [u32; N]) -> Self {
        Self(WeierstrassPoint::Affine(limbs))
    }

    fn identity() -> Self {
        Self::infinity()
    }

    fn is_identity(&self) -> bool {
        self.is_infinity()
    }

    fn limbs_ref(&self) -> &[u32; N] {
        match &self.0 {
            WeierstrassPoint::Infinity => panic!("Infinity point has no limbs"),
            WeierstrassPoint::Affine(limbs) => limbs,
        }
    }

    fn limbs_mut(&mut self) -> &mut [u32; N] {
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
