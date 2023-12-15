use std::iter::once;

use p3_air::VirtualPairCol;
use p3_field::Field;

use crate::{
    air::Word,
    lookup::{Interaction, InteractionKind},
    runtime::Opcode,
};

pub mod add;
pub mod bitwise;
pub mod lt;
pub mod shift;
pub mod sub;

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
