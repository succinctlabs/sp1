use crate::{
    syscall_secp256k1_add, syscall_secp256k1_double,
    utils::{AffinePoint, WeierstrassAffinePoint, WeierstrassPoint},
};

/// The number of limbs in [Secp256k1AffinePoint].
pub const N: usize = 16;

/// An affine point on the Secp256k1 curve.
#[derive(Copy, Clone)]
#[repr(align(4))]
pub struct Secp256k1AffinePoint(pub WeierstrassPoint<N>);

impl WeierstrassAffinePoint<N> for Secp256k1AffinePoint {
    fn infinity() -> Self {
        Self(WeierstrassPoint::Infinity)
    }
}

impl AffinePoint<N> for Secp256k1AffinePoint {
    /// The values are taken from https://en.bitcoin.it/wiki/Secp256k1.
    const GENERATOR: [u32; N] = [
        385357720, 1509065051, 768485593, 43777243, 3464956679, 1436574357, 4191992748, 2042521214,
        4212184248, 2621952143, 2793755673, 4246189128, 235997352, 1571093500, 648266853,
        1211816567,
    ];

    fn new(limbs: [u32; N]) -> Self {
        Self(WeierstrassPoint::Affine(limbs))
    }

    fn is_infinity(&self) -> bool {
        match self.0 {
            WeierstrassPoint::Infinity => true,
            WeierstrassPoint::Affine(_) => false,
        }
    }

    fn limbs_ref(&self) -> &[u32; N] {
        match &self.0 {
            WeierstrassPoint::Infinity => panic!("infinity point has no limbs"),
            WeierstrassPoint::Affine(limbs) => limbs,
        }
    }

    fn limbs_mut(&mut self) -> &mut [u32; N] {
        match &mut self.0 {
            WeierstrassPoint::Infinity => panic!("infinity point has no limbs"),
            WeierstrassPoint::Affine(limbs) => limbs,
        }
    }

    fn add_assign(&mut self, other: &Self) {
        let a = self.limbs_mut();
        let b = other.limbs_ref();
        unsafe {
            syscall_secp256k1_add(a, b);
        }
    }

    fn double(&mut self) {
        match self.0 {
            WeierstrassPoint::Infinity => (),
            WeierstrassPoint::Affine(_) => {
                let a = self.limbs_mut();
                unsafe {
                    syscall_secp256k1_double(a);
                }
            }
        };
    }
}
