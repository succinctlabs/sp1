use p3_field::{AbstractField, Field};
use sp1_core::utils::poseidon2_instance::RC_16_30_U32;

use crate::runtime::POSEIDON2_WIDTH;

use super::{MATRIX_DIAG_16_BABYBEAR_U32, P_END, ROUNDS, ROUNDS_F_BEGINNING};

pub fn permute_mut_round<F>(state: &mut [F; POSEIDON2_WIDTH], round: usize)
where
    F: AbstractField,
{
    apply_round_constants(state, round);
    let is_initial_layer = round == 0;
    let is_external_layer = !is_initial_layer
        && (round - 1 < ROUNDS_F_BEGINNING || (P_END < round && (round - 1) < ROUNDS));

    let mut add_rc = state.clone();
    apply_sbox(state);
    let mut sbox = state.clone();

    match (is_initial_layer, is_external_layer) {
        (true, _) => {
            apply_linear_layer(&mut add_rc, round);
            *state = add_rc;
        }
        (_, true) => {
            apply_linear_layer(&mut sbox, round);
            *state = sbox;
        }
        _ => {
            add_rc[0] = sbox[0].clone();
            apply_linear_layer(&mut add_rc, round);
            *state = add_rc;
        }
    }
}

pub fn apply_round_constants<F>(state: &mut [F; POSEIDON2_WIDTH], round: usize)
where
    F: AbstractField,
{
    let is_initial_layer = round == 0;
    let is_external_layer = !is_initial_layer
        && (round - 1 < ROUNDS_F_BEGINNING || (P_END < round && (round - 1) < ROUNDS));

    match (is_initial_layer, is_external_layer) {
        (true, _) => {}
        (_, true) => {
            state
                .iter_mut()
                .zip(RC_16_30_U32[round - 1].iter())
                .for_each(|(s, &rc)| *s += F::from_wrapped_u32(rc));
        }
        _ => {
            state[0] += F::from_wrapped_u32(RC_16_30_U32[round - 1][0]);
        }
    }
}

#[allow(clippy::needless_range_loop)]
fn apply_sbox<F>(state: &mut [F; POSEIDON2_WIDTH])
where
    F: AbstractField,
{
    for i in 0..POSEIDON2_WIDTH {
        let x = state[i].clone();
        let x2 = x.clone() * x.clone();
        let x4 = x2.clone() * x2.clone();
        state[i] = x4 * x2 * x;
    }
}

fn apply_linear_layer<AF, F>(state: &mut [AF; POSEIDON2_WIDTH], round: usize)
where
    AF: AbstractField<F = F>,
    F: Field,
{
    let is_initial_layer = round == 0;
    let is_external_layer = round != 0
        && (((round - 1) < ROUNDS_F_BEGINNING) || (P_END <= (round - 1) && (round - 1) < ROUNDS));

    if is_initial_layer || is_external_layer {
        for j in (0..POSEIDON2_WIDTH).step_by(4) {
            apply_m_4(&mut state[j..j + 4]);
        }
        let sums: [AF; 4] = core::array::from_fn(|k| {
            (0..POSEIDON2_WIDTH)
                .step_by(4)
                .map(|j| state[j + k].clone())
                .sum::<AF>()
        });
        for j in 0..POSEIDON2_WIDTH {
            state[j] += sums[j % 4].clone();
        }
    } else {
        let matmul_constants: [F; POSEIDON2_WIDTH] = MATRIX_DIAG_16_BABYBEAR_U32
            .iter()
            .map(|x| F::from_wrapped_u32(*x))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        matmul_internal(state, matmul_constants);
    }
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
