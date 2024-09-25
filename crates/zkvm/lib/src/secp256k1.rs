use crate::{syscall_secp256k1_add, syscall_secp256k1_double, utils::AffinePoint};

/// The number of limbs in [Secp256k1AffinePoint].
pub const N: usize = 16;

/// An affine point on the Secp256k1 curve.
#[derive(Copy, Clone)]
#[repr(align(4))]
pub struct Secp256k1AffinePoint(pub [u32; N]);

impl AffinePoint<N> for Secp256k1AffinePoint {
    /// The values are taken from https://en.bitcoin.it/wiki/Secp256k1.
    const GENERATOR: [u32; N] = [
        385357720, 1509065051, 768485593, 43777243, 3464956679, 1436574357, 4191992748, 2042521214,
        4212184248, 2621952143, 2793755673, 4246189128, 235997352, 1571093500, 648266853,
        1211816567,
    ];

    fn new(limbs: [u32; N]) -> Self {
        Self(limbs)
    }

    fn limbs_ref(&self) -> &[u32; N] {
        &self.0
    }

    fn limbs_mut(&mut self) -> &mut [u32; N] {
        &mut self.0
    }

    fn add_assign(&mut self, other: &Self) {
        let a = self.limbs_mut();
        let b = other.limbs_ref();

        // Case 1: Both points are infinity.
        if a == &[0; N] && b == &[0; N] {
            *self = Self::infinity();
            return;
        }

        // Case 2: `self` is infinity.
        if a == &[0; N] {
            *self = *other;
            return;
        }

        // Case 3: `other` is infinity.
        if b == &[0; N] {
            return;
        }

        // Case 4: a = b.
        if a == b {
            self.double();
            return;
        }

        // Case 5: a = -b
        if a[..(N / 2)] == b[..(N / 2)]
            && a[(N / 2)..].iter().zip(&b[(N / 2)..]).all(|(y1, y2)| y1.wrapping_add(*y2) == 0)
        {
            *self = Self::infinity();
            return;
        }

        // Case 6: General addition.
        unsafe {
            syscall_secp256k1_add(a, b);
        }
    }

    fn double(&mut self) {
        let a = self.limbs_mut();
        unsafe {
            syscall_secp256k1_double(a);
        }
    }
}

impl Secp256k1AffinePoint {
    fn infinity() -> Self {
        Self([0; N])
    }
}
