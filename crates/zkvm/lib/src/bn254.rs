use num_bigint::BigUint;

use crate::{
    syscall_bn254_add, syscall_bn254_double,
    utils::{AffinePoint, WeierstrassAffinePoint},
};

/// The number of limbs in [Bn254AffinePoint].
pub const N: usize = 16;

/// An affine point on the Bn254 curve.
#[derive(Copy, Clone)]
#[repr(align(4))]
pub struct Bn254AffinePoint(pub [u32; N]);

impl WeierstrassAffinePoint<N> for Bn254AffinePoint {
    fn modulus() -> BigUint {
        BigUint::from_bytes_le(&[
            0x01, 0x00, 0x00, 0x00, 0x3F, 0xF5, 0xE1, 0x43, 0x91, 0x70, 0xB9, 0x79, 0x48, 0xE8,
            0x33, 0x28, 0x5D, 0x58, 0x81, 0x81, 0xB6, 0x45, 0x50, 0xB8, 0x29, 0xA0, 0x31, 0xE1,
            0x72, 0x4E, 0x64, 0x30,
        ])
    }
}

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

    fn complete_add_assign(&mut self, other: &Self) {
        self.weierstrass_add_assign(other);
    }

    fn add_assign(&mut self, other: &Self) {
        let a = self.limbs_mut();
        let b = other.limbs_ref();
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
