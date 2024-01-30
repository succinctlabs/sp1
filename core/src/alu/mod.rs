pub mod add;
pub mod bitwise;
pub mod divrem;
pub mod lt;
pub mod mul;
pub mod sll;
pub mod sr;
pub mod sub;

pub use add::*;
pub use bitwise::*;
pub use lt::*;
pub use sll::*;
pub use sr::*;
pub use sub::*;

use crate::runtime::Opcode;

/// A standard format for describing ALU operations that need to be proven.
#[derive(Debug, Clone, Copy)]
pub struct AluEvent {
    /// The clock cycle that the operation occurs on.
    pub clk: u32,

    /// The opcode of the operation.
    pub opcode: Opcode,

    /// The result of the operation.
    pub a: u32,

    /// The first input operand.
    pub b: u32,

    // The second input operand.
    pub c: u32,
}

impl AluEvent {
    /// Creates a new `AluEvent`.
    pub fn new(clk: u32, opcode: Opcode, a: u32, b: u32, c: u32) -> Self {
        Self {
            clk,
            opcode,
            a,
            b,
            c,
        }
    }
}
