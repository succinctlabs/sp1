#![allow(clippy::needless_range_loop)]

use crate::poseidon2::external::WIDTH;
use p3_field::{AbstractField, Field, PrimeField32};

mod external;

pub use external::Poseidon2Chip;

#[derive(Debug, Clone)]
pub struct Poseidon2Event<F> {
    pub input: [F; WIDTH],
}

// TODO: Make this public inside Plonky3 and import directly.
pub fn apply_m_4<AF>(x: &mut [AF])
where
    AF: AbstractField,
{
    let t0 = x[0].clone() + x[1].clone();
    let t1 = x[2].clone() + x[3].clone();
    let t2 = x[1].clone() + x[1].clone() + t1.clone();
    let t3 = x[3].clone() + x[3].clone() + t0.clone();
    let t4 = t1.clone() + t1.clone() + t1.clone() + t1 + t3.clone();
    let t5 = t0.clone() + t0.clone() + t0.clone() + t0 + t2.clone();
    let t6 = t3 + t5.clone();
    let t7 = t2 + t4.clone();
    x[0] = t6;
    x[1] = t5;
    x[2] = t7;
    x[3] = t4;
}

// TODO: Make this public inside Plonky3 and import directly.
pub fn matmul_internal<F: Field, AF: AbstractField<F = F>, const WIDTH: usize>(
    state: &mut [AF; WIDTH],
    mat_internal_diag_m_1: [F; WIDTH],
) {
    let sum: AF = state.iter().cloned().sum();
    for i in 0..WIDTH {
        state[i] *= AF::from_f(mat_internal_diag_m_1[i]);
        state[i] += sum.clone();
    }
}

pub(crate) fn external_linear_layer<F: PrimeField32>(input: &[F; WIDTH], output: &mut [F; WIDTH]) {
    output.copy_from_slice(input);
    for j in (0..WIDTH).step_by(4) {
        apply_m_4(&mut output[j..j + 4]);
    }
    let sums: [F; 4] =
        core::array::from_fn(|k| (0..WIDTH).step_by(4).map(|j| output[j + k]).sum::<F>());

    for j in 0..WIDTH {
        output[j] += sums[j % 4];
    }
}

pub(crate) fn internal_linear_layer<F: PrimeField32>(input: &[F; WIDTH], output: &mut [F; WIDTH]) {
    output.copy_from_slice(input);
    let matmul_constants: [F; WIDTH] = MATRIX_DIAG_16_BABYBEAR_U32
        .iter()
        .map(|x| F::from_wrapped_u32(*x))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    matmul_internal(output, matmul_constants);
}

pub const MATRIX_DIAG_16_BABYBEAR_U32: [u32; 16] = [
    0x0a632d94, 0x6db657b7, 0x56fbdc9e, 0x052b3d8a, 0x33745201, 0x5c03108c, 0x0beba37b, 0x258c2e8b,
    0x12029f39, 0x694909ce, 0x6d231724, 0x21c3b222, 0x3c0904a5, 0x01d6acda, 0x27705c83, 0x5231c802,
];
