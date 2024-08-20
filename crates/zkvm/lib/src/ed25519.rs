use crate::{syscall_ed_add, utils::AffinePoint};

/// The number of limbs in [Ed25519AffinePoint].
pub const N: usize = 16;

/// An affine point on the Ed25519 curve.
#[derive(Copy, Clone)]
#[repr(align(4))]
pub struct Ed25519AffinePoint(pub [u32; N]);

impl AffinePoint<N> for Ed25519AffinePoint {
    /// The generator/base point for the Ed25519 curve. Reference: https://datatracker.ietf.org/doc/html/rfc7748#section-4.1
    const GENERATOR: [u32; N] = [
        216936062, 3086116296, 2351951131, 1681893421, 3444223839, 2756123356, 3800373269,
        3284567716, 2518301344, 752319464, 3983256831, 1952656717, 3669724772, 3793645816,
        3665724614, 2969860233,
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
            syscall_ed_add(a, b);
        }
    }

    /// In Edwards curves, doubling is the same as adding a point to itself.
    fn double(&mut self) {
        let a = self.limbs_mut();
        unsafe {
            syscall_ed_add(a, a);
        }
    }
}

impl Ed25519AffinePoint {
    const IDENTITY: [u32; N] = [0; N];

    pub fn identity() -> Self {
        Self(Self::IDENTITY)
    }
}
