use crate::{
    syscall_secp256k1_add, syscall_secp256k1_double, syscall_secp256k1_mul,
    utils::{AffinePoint, WeierstrassAffinePoint, WeierstrassPoint},
};

/// The number of limbs in [Secp256k1Point].
pub const N: usize = 8;

/// An affine point on the Secp256k1 curve.
#[derive(Copy, Clone, Debug)]
#[repr(align(8))]
pub struct Secp256k1Point(pub WeierstrassPoint<N>);

impl WeierstrassAffinePoint<N> for Secp256k1Point {
    fn infinity() -> Self {
        Self(WeierstrassPoint::Infinity)
    }

    fn is_infinity(&self) -> bool {
        matches!(self.0, WeierstrassPoint::Infinity)
    }
}

impl AffinePoint<N> for Secp256k1Point {
    /// The values are taken from https://en.bitcoin.it/wiki/Secp256k1.
    const GENERATOR: [u64; N] = [
        6481385041966929816,
        188021827762530521,
        6170039885052185351,
        8772561819708210092,
        11261198710074299576,
        18237243440184513561,
        6747795201694173352,
        5204712524664259685,
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
            syscall_secp256k1_add(a, b);
        }
    }

    fn complete_add_assign(&mut self, other: &Self) {
        self.weierstrass_add_assign(other);
    }

    fn double(&mut self) {
        match &mut self.0 {
            WeierstrassPoint::Infinity => (),
            WeierstrassPoint::Affine(limbs) => unsafe {
                syscall_secp256k1_double(limbs);
            },
        }
    }

    fn mul_assign(&mut self, scalar: &[u64]) {
        debug_assert_eq!(scalar.len(), N / 2);
        match &mut self.0 {
            // k · ∞ = ∞ for any k.
            WeierstrassPoint::Infinity => (),
            WeierstrassPoint::Affine(limbs) => {
                // 0 · P = ∞. The syscall operates in affine coordinates and has no representation
                // for the result, so short-circuit here.
                if scalar.iter().all(|&w| w == 0) {
                    *self = Self::infinity();
                    return;
                }
                unsafe {
                    syscall_secp256k1_mul(limbs, scalar.as_ptr() as *const [u64; 4]);
                }
            }
        }
    }

    fn multi_scalar_multiplication(
        a_bits_le: &[bool],
        a: Self,
        b_bits_le: &[bool],
        b: Self,
    ) -> Self {
        fn pack_bits_le(bits: &[bool]) -> [u64; 4] {
            core::array::from_fn(|w| {
                bits[w * 64..(w + 1) * 64]
                    .iter()
                    .enumerate()
                    .fold(0u64, |acc, (i, &b)| acc | ((b as u64) << i))
            })
        }

        let mut ax = a;
        ax.mul_assign(&pack_bits_le(a_bits_le));
        let mut bx = b;
        bx.mul_assign(&pack_bits_le(b_bits_le));
        ax.complete_add_assign(&bx);
        ax
    }
}
