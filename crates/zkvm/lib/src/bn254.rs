use crate::{syscall_bn254_add, syscall_bn254_double, utils::AffinePoint};

/// The number of limbs in [Bn254AffinePoint].
pub const N: usize = 16;

/// An affine point on the Bn254 curve.
#[derive(Copy, Clone)]
#[repr(align(4))]
pub struct Bn254AffinePoint(pub [u32; N]);

impl AffinePoint<N> for Bn254AffinePoint {
    /// The generator has been taken from py_pairing python library by the Ethereum Foundation:
    ///
    /// https://github.com/ethereum/py_pairing/blob/5f609da/py_ecc/bn128/bn128_field_elements.py
    const GENERATOR: [u32; N] = [1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0];

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
            syscall_bn254_add(a, b);
        }
    }

    fn double(&mut self) {
        let a = self.limbs_mut();
        unsafe {
            syscall_bn254_double(a);
        }
    }
}

impl Bn254AffinePoint {
    fn infinity() -> Self {
        Self([0; N])
    }
}
