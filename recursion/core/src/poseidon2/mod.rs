use p3_field::{AbstractField, Field};

mod external;

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

// TODO: Make this public inside Plonky3 and import directly.
pub const MATRIX_DIAG_16_BABYBEAR_U32: [u32; 16] = [
    0x0a632d94, 0x6db657b7, 0x56fbdc9e, 0x052b3d8a, 0x33745201, 0x5c03108c, 0x0beba37b, 0x258c2e8b,
    0x12029f39, 0x694909ce, 0x6d231724, 0x21c3b222, 0x3c0904a5, 0x01d6acda, 0x27705c83, 0x5231c802,
];
