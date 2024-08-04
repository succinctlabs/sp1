use crate::utils::AffinePoint;
use crate::{syscall_bls12381_add, syscall_bls12381_double};

/// The number of limbs in [Bls12381AffinePoint].
pub const N: usize = 24;

/// An affine point on the BLS12-381 curve.
#[derive(Copy, Clone)]
#[repr(align(4))]
pub struct Bls12381AffinePoint(pub [u32; N]);

impl AffinePoint<N> for Bls12381AffinePoint {
    /// The generator was taken from "py_ecc" python library by the Ethereum Foundation:
    ///
    /// https://github.com/ethereum/py_ecc/blob/7b9e1b3/py_ecc/bls12_381/bls12_381_curve.py#L38-L45
    const GENERATOR: [u32; N] = [
        3676489403, 4214943754, 4185529071, 1817569343, 387689560, 2706258495, 2541009157,
        3278408783, 1336519695, 647324556, 832034708, 401724327, 1187375073, 212476713, 2726857444,
        3493644100, 738505709, 14358731, 3587181302, 4243972245, 1948093156, 2694721773,
        3819610353, 146011265,
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
        unsafe {
            syscall_bls12381_add(a, b);
        }
    }

    fn double(&mut self) {
        let a = self.limbs_mut();
        unsafe {
            syscall_bls12381_double(a);
        }
    }
}
