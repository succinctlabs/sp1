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

#[derive(Debug, Clone, Copy)]
pub struct AluEvent {
    pub clk: u32,
    pub opcode: Opcode,
    pub a: u32,
    pub b: u32,
    pub c: u32,
}

impl AluEvent {
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
