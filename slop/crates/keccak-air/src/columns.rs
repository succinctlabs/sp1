use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

use crate::constants::R;
use crate::{NUM_ROUNDS, RC_BIT_POSITIONS, U64_LIMBS};

/// Optimized Keccak-f row representation.
///
/// Nonlinear Keccak intermediates are reconstructed by the AIR. Input and
/// output limbs remain explicit because SP1 interactions must be affine.
#[derive(Debug)]
#[repr(C)]
pub struct KeccakCols<T> {
    /// One-hot selector for the active Keccak round.
    pub step_flags: [T; NUM_ROUNDS],

    /// Theta column parities.
    pub c: [[T; 64]; 5],

    /// Theta output parities.
    pub c_prime: [[T; 64]; 5],

    /// State after theta, stored in y, x, z order.
    pub a_prime: [[[T; 64]; 5]; 5],

    /// Chi bits at the only positions touched by Keccak round constants.
    pub a_prime_prime_0_0_rc_bits: [T; RC_BIT_POSITIONS.len()],

    /// Input limbs used by the affine local interaction.
    pub input_limbs: [[[T; U64_LIMBS]; 5]; 5],

    /// Post-iota output limbs used by the affine local interaction.
    pub output_limbs: [[[T; U64_LIMBS]; 5]; 5],
}

impl<T: Copy> KeccakCols<T> {
    /// Returns a rho/pi output bit as an alias into `a_prime`.
    pub fn b(&self, x: usize, y: usize, z: usize) -> T {
        debug_assert!(x < 5);
        debug_assert!(y < 5);
        debug_assert!(z < 64);

        let a = (x + 3 * y) % 5;
        let b = x;
        let rot = R[a][b] as usize;
        self.a_prime[b][a][(z + 64 - rot) % 64]
    }
}

pub const NUM_KECCAK_COLS: usize = size_of::<KeccakCols<u8>>();

impl<T> Borrow<KeccakCols<T>> for [T] {
    fn borrow(&self) -> &KeccakCols<T> {
        debug_assert_eq!(self.len(), NUM_KECCAK_COLS);
        let (prefix, rows, suffix) = unsafe { self.align_to::<KeccakCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment should match");
        debug_assert!(suffix.is_empty(), "alignment should match");
        debug_assert_eq!(rows.len(), 1);
        &rows[0]
    }
}

impl<T> BorrowMut<KeccakCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut KeccakCols<T> {
        debug_assert_eq!(self.len(), NUM_KECCAK_COLS);
        let (prefix, rows, suffix) = unsafe { self.align_to_mut::<KeccakCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment should match");
        debug_assert!(suffix.is_empty(), "alignment should match");
        debug_assert_eq!(rows.len(), 1);
        &mut rows[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optimized_width_is_stable() {
        assert_eq!(NUM_KECCAK_COLS, 2_471);
    }
}
