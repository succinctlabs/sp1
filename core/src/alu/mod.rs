use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

use crate::{lookup::Interaction, runtime::Opcode, Runtime};
mod add;
mod bitwise;
mod shift;
mod sub;

pub trait Chip<F: PrimeField> {
    fn generate_trace(&self, runtime: &mut Runtime) -> RowMajorMatrix<F>;

    fn interactions(&self) -> Vec<Interaction<F>>;
}

#[derive(Debug, Clone, Copy)]
pub struct AluEvent {
    pub clk: u32,
    pub opcode: Opcode,
    pub a: u32,
    pub b: u32,
    pub c: u32,
}

pub const fn indices_arr<const N: usize>() -> [usize; N] {
    let mut indices_arr = [0; N];
    let mut i = 0;
    while i < N {
        indices_arr[i] = i;
        i += 1;
    }
    indices_arr
}

pub fn u32_to_u8_limbs(value: u32) -> [u8; 4] {
    let mut limbs = [0u8; 4];
    limbs[0] = (value & 0xFF) as u8;
    limbs[1] = ((value >> 8) & 0xFF) as u8;
    limbs[2] = ((value >> 16) & 0xFF) as u8;
    limbs[3] = ((value >> 24) & 0xFF) as u8;
    limbs
}

pub fn pad_to_power_of_two<const N: usize, T: Clone + Default>(values: &mut Vec<T>) {
    debug_assert!(values.len() % N == 0);
    let n_real_rows = values.len() / N;
    values.resize(n_real_rows.next_power_of_two() * N, T::default());
}
