//! Diffusion matrix for BLS12-377 Fr
//!
//! Reference (structure): `p3-bn254-fr` diffusion matrix implementation, based on
//! HorizenLabs Poseidon2 instances.

use std::sync::OnceLock;

use p3_field::AbstractField;
use p3_poseidon2::{matmul_internal, DiffusionPermutation};
use p3_symmetric::Permutation;
use serde::{Deserialize, Serialize};

use crate::Bls12377Fr;

#[inline]
fn get_diffusion_matrix_3() -> &'static [Bls12377Fr; 3] {
    static MAT_DIAG3_M_1: OnceLock<[Bls12377Fr; 3]> = OnceLock::new();
    MAT_DIAG3_M_1.get_or_init(|| [Bls12377Fr::one(), Bls12377Fr::one(), Bls12377Fr::two()])
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiffusionMatrixBls12377;

impl<AF: AbstractField<F = Bls12377Fr>> Permutation<[AF; 3]> for DiffusionMatrixBls12377 {
    fn permute_mut(&self, state: &mut [AF; 3]) {
        matmul_internal::<Bls12377Fr, AF, 3>(state, *get_diffusion_matrix_3());
    }
}

impl<AF: AbstractField<F = Bls12377Fr>> DiffusionPermutation<AF, 3> for DiffusionMatrixBls12377 {}


