use p3_field::{AbstractField, Field, PrimeField32};

mod external;

pub use external::*;
use sp1_core::utils::poseidon2_instance::RC_16_30_U32;

/// The number of external rounds in the Poseidon permutation.
pub(crate) const ROUNDS_F: usize = 8;

// The number of internal rounds in the Poseidon permutation.
pub(crate) const ROUNDS_P: usize = 22;

// The total number of rounds in the Poseidon permutation.
pub(crate) const ROUNDS: usize = ROUNDS_F + ROUNDS_P;

pub(crate) const ROUNDS_F_BEGINNING: usize = ROUNDS_F / 2;
pub(crate) const P_END: usize = ROUNDS_F_BEGINNING + ROUNDS_P;

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

pub fn permute_mut_round<F>(state: &mut [F; WIDTH], round: usize)
where
    F: AbstractField,
{
    let round = round % 31;
    apply_round_constants(state, round);
    apply_sbox(state);
    apply_linear_layer(state, round);
}

fn apply_round_constants<F>(state: &mut [F; WIDTH], round: usize)
where
    F: AbstractField,
{
    let is_initial_layer = round == 0;
    let is_external_layer = round != 0
        && (((round - 1) < ROUNDS_F_BEGINNING) || (P_END <= (round - 1) && (round - 1) < ROUNDS));

    if is_initial_layer {
        // Don't apply the round constants in the initial layer.
    } else if is_external_layer {
        // Apply the round constants in the external layers.
        for j in 0..WIDTH {
            state[j] += F::from_wrapped_u32(RC_16_30_U32[round - 1][j]);
        }
    } else {
        // Apply the round constants only on the first element in the internal layers.
        state[0] += F::from_wrapped_u32(RC_16_30_U32[round - 1][0]);
    }
}

fn apply_sbox<F>(state: &mut [F; WIDTH])
where
    F: AbstractField,
{
    for i in 0..WIDTH {
        let x = state[i].clone();
        let x2 = x.clone() * x.clone();
        let x4 = x2.clone() * x2.clone();
        state[i] = x4 * x2 * x;
    }
}

fn apply_linear_layer<AF, F>(state: &mut [AF; WIDTH], round: usize)
where
    AF: AbstractField<F = F>,
    F: Field,
{
    let matmul_constants: [F; WIDTH] = MATRIX_DIAG_16_BABYBEAR_U32
        .iter()
        .map(|x| F::from_wrapped_u32(*x))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let is_initial_layer = round == 0;
    let is_external_layer = round != 0
        && (((round - 1) < ROUNDS_F_BEGINNING) || (P_END <= (round - 1) && (round - 1) < ROUNDS));

    if is_initial_layer || is_external_layer {
        apply_m_4(state);
        let sums: [AF; 4] = core::array::from_fn(|k| {
            (0..WIDTH)
                .step_by(4)
                .map(|j| state[j + k].clone())
                .sum::<AF>()
        });
        for j in 0..WIDTH {
            state[j] += sums[j % 4].clone();
        }
    } else {
        matmul_internal(state, matmul_constants);
    }
}
