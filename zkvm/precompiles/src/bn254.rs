use crate::{syscall_bn254_add, syscall_bn254_double};
use core::convert::TryInto;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Bn254AffinePoint {
    limbs: [u32; 16],
}

impl Bn254AffinePoint {
    pub fn from(x: [u32; 8], y: [u32; 8]) -> Self {
        let mut limbs = [0u32; 16];
        limbs[..8].copy_from_slice(&x);
        limbs[8..].copy_from_slice(&y);
        Self { limbs }
    }

    pub const fn from_limbs(limbs: [u32; 16]) -> Self {
        Self { limbs }
    }

    pub fn from_u8_limbs(limbs: [u8; 64]) -> Self {
        let u32_limbs = limbs
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<u32>>()
            .try_into()
            .unwrap();
        Self { limbs: u32_limbs }
    }

    pub fn add_assign(&mut self, other: &Bn254AffinePoint) {
        unsafe {
            syscall_bn254_add(self.limbs.as_mut_ptr(), other.limbs.as_ptr());
        }
    }

    pub fn double(&mut self) {
        unsafe {
            syscall_bn254_double(self.limbs.as_mut_ptr());
        }
    }

    pub fn mul_assign(&mut self, scalar: &[u32; 8]) {
        let mut res: Option<Bn254AffinePoint> = None;
        let mut temp = *self;

        // Iterate over the scalar bits in little-endian order
        for &word in scalar.iter() {
            for i in 0..32 {
                let bit = (word >> i) & 1 != 0;

                if bit {
                    match res.as_mut() {
                        Some(res) => res.add_assign(&temp),
                        None => res = Some(temp),
                    };
                }

                temp.double();
            }
        }

        *self = res.unwrap();
    }

    pub fn to_u8_limbs(&self) -> [u8; 64] {
        self.limbs
            .iter()
            .enumerate()
            .fold([0u8; 64], |mut acc, (i, &limb)| {
                acc[i * 4..(i + 1) * 4].copy_from_slice(&limb.to_le_bytes());
                acc
            })
    }
}

pub fn bn254_mul(point: &mut Bn254AffinePoint, scalar: &[u32; 8]) {
    point.mul_assign(scalar)
}
