//! Higher-level guest API for SP1's septic curve precompile.
//!
//! The septic curve is `y^2 = x^3 + 45x + 41z^3` over `F_{p^7} = F_p[z]/(z^7 - 3z - 5)`,
//! where `p` is the KoalaBear prime. Each point is represented as 14 KoalaBear
//! field elements `[x0..x6, y0..y6]`, packed into 7 u64 words (two u32s per u64,
//! little-endian) for 8-byte alignment.

use crate::{
    syscall_septic_add, syscall_septic_double, syscall_septic_scalar_mul, syscall_septic_verify,
};

/// A septic curve point.
///
/// The `data` field stores 7 u64 words representing 14 KoalaBear field elements:
/// `[x0..x6, y0..y6]`, two field elements per u64 (little-endian).
#[derive(Clone, Copy, Debug)]
#[repr(C, align(8))]
pub struct SepticPoint {
    pub data: [u64; 7],
}

impl SepticPoint {
    /// Construct a `SepticPoint` from 7-element x and y coordinate arrays.
    pub fn new(x: [u32; 7], y: [u32; 7]) -> Self {
        let mut elems = [0u32; 14];
        elems[..7].copy_from_slice(&x);
        elems[7..].copy_from_slice(&y);
        let mut data = [0u64; 7];
        for i in 0..7 {
            data[i] = (elems[2 * i] as u64) | ((elems[2 * i + 1] as u64) << 32);
        }
        SepticPoint { data }
    }

    /// Return the unpacked 14 field elements `[x0..x6, y0..y6]`.
    pub fn limbs(&self) -> [u32; 14] {
        let mut out = [0u32; 14];
        for i in 0..7 {
            out[2 * i] = self.data[i] as u32;
            out[2 * i + 1] = (self.data[i] >> 32) as u32;
        }
        out
    }

    /// x-coordinate as 7 KoalaBear limbs.
    pub fn x(&self) -> [u32; 7] {
        let l = self.limbs();
        [l[0], l[1], l[2], l[3], l[4], l[5], l[6]]
    }

    /// y-coordinate as 7 KoalaBear limbs.
    pub fn y(&self) -> [u32; 7] {
        let l = self.limbs();
        [l[7], l[8], l[9], l[10], l[11], l[12], l[13]]
    }

    /// Point addition: `self + other` (incomplete — assumes `self != other`).
    pub fn add(&self, other: &SepticPoint) -> SepticPoint {
        let mut result = *self;
        unsafe {
            syscall_septic_add(&mut result.data as *mut [u64; 7], &other.data as *const [u64; 7]);
        }
        result
    }

    /// Point doubling: `2 * self`.
    pub fn double(&self) -> SepticPoint {
        let mut result = *self;
        unsafe {
            syscall_septic_double(&mut result.data as *mut [u64; 7]);
        }
        result
    }

    /// Scalar multiplication via double-and-add.
    ///
    /// `scalar` is little-endian limbs. Iterates each bit, accumulating the
    /// running sum. Returns the identity-like all-zero point if `scalar == 0`.
    pub fn scalar_mul(&self, scalar: &[u32]) -> SepticPoint {
        let mut result_set = false;
        let mut result = SepticPoint { data: [0u64; 7] };
        let mut temp = *self;

        for limb in scalar {
            for bit in 0..32 {
                if (limb >> bit) & 1 == 1 {
                    if !result_set {
                        result = temp;
                        result_set = true;
                    } else {
                        result = result.add(&temp);
                    }
                }
                temp = temp.double();
            }
        }
        result
    }

    /// Scalar multiplication via the `SEPTIC_SCALAR_MUL` precompile (single syscall).
    ///
    /// `scalar` is 8 little-endian u32 limbs, packed into 4 u64 words for the
    /// syscall. Compared to [`Self::scalar_mul`] this performs the entire
    /// double-and-add loop inside the executor, avoiding ~325 individual syscalls.
    pub fn scalar_mul_single(&self, scalar: &[u32; 8]) -> SepticPoint {
        let mut result = *self;
        let mut scalar_packed = [0u64; 4];
        for i in 0..4 {
            scalar_packed[i] = (scalar[2 * i] as u64) | ((scalar[2 * i + 1] as u64) << 32);
        }
        unsafe {
            syscall_septic_scalar_mul(
                &mut result.data as *mut [u64; 7],
                &scalar_packed as *const [u64; 4],
            );
        }
        result
    }
}

/// Schnorr verification helper: compute `s * G + e * A` via the `SEPTIC_VERIFY`
/// precompile (single syscall), where `G` is the hardcoded septic curve
/// generator. Uses Shamir's trick inside the executor, so it costs ~381 EC
/// operations vs. ~651 for two independent `scalar_mul_single` calls.
///
/// The caller compares the returned point against `R` to complete the Schnorr
/// verification equation.
pub fn schnorr_compute(a: &SepticPoint, s: &[u32; 8], e: &[u32; 8]) -> SepticPoint {
    let mut buf = [0u64; 15];

    buf[0..7].copy_from_slice(&a.data);

    for i in 0..4 {
        buf[7 + i] = (s[2 * i] as u64) | ((s[2 * i + 1] as u64) << 32);
    }
    for i in 0..4 {
        buf[11 + i] = (e[2 * i] as u64) | ((e[2 * i + 1] as u64) << 32);
    }

    unsafe {
        syscall_septic_verify(&mut buf as *mut [u64; 15]);
    }

    let mut result_data = [0u64; 7];
    result_data.copy_from_slice(&buf[0..7]);
    SepticPoint { data: result_data }
}
