//! Batched execution support for adjacent independent Poseidon2 instructions.

use slop_koala_bear::{DiffusionMatrixKoalaBear, KoalaBear};
use slop_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};

use crate::{PERMUTATION_WIDTH, POSEIDON2_SBOX_DEGREE};

type KoalaBearPerm = Poseidon2<
    KoalaBear,
    Poseidon2ExternalMatrixGeneral,
    DiffusionMatrixKoalaBear,
    PERMUTATION_WIDTH,
    POSEIDON2_SBOX_DEGREE,
>;

/// An 8-lane batched Poseidon2 permutation.
///
/// The executor uses this to run adjacent, pairwise-independent `Poseidon2` instructions
/// (as emitted by the batched DSL operation) as one SIMD permutation where the platform
/// supports it.
pub trait Poseidon2Batch8<F> {
    /// Permutes the 8 states in place. Returns `false` when no batched implementation is
    /// available, in which case the states are left untouched and the caller must fall back
    /// to scalar permutations.
    fn permute_batch8(&self, states: &mut [[F; PERMUTATION_WIDTH]; 8]) -> bool;
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
impl Poseidon2Batch8<KoalaBear> for KoalaBearPerm {
    fn permute_batch8(&self, states: &mut [[KoalaBear; PERMUTATION_WIDTH]; 8]) -> bool {
        use slop_koala_bear::PackedKoalaBearAVX2;
        use slop_symmetric::Permutation;

        // Transpose the 8 states into 16 packed rows, one lane per state.
        let mut rows: [PackedKoalaBearAVX2; PERMUTATION_WIDTH] = core::array::from_fn(|i| {
            PackedKoalaBearAVX2(core::array::from_fn(|lane| states[lane][i]))
        });
        self.permute_mut(&mut rows);
        for (i, row) in rows.iter().enumerate() {
            for (lane, state) in states.iter_mut().enumerate() {
                state[i] = row.0[lane];
            }
        }
        true
    }
}

#[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
impl Poseidon2Batch8<KoalaBear> for KoalaBearPerm {
    fn permute_batch8(&self, _states: &mut [[KoalaBear; PERMUTATION_WIDTH]; 8]) -> bool {
        false
    }
}
