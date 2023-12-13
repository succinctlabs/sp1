use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

use crate::{runtime::Opcode, Runtime};
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
