use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

use crate::{lookup::Interaction, runtime::Opcode, Runtime};
mod add;
mod bitwise;
mod shift;
mod sub;

#[derive(Debug, Clone, Copy)]
pub struct AluEvent {
    pub clk: u32,
    pub opcode: Opcode,
    pub a: u32,
    pub b: u32,
    pub c: u32,
}
