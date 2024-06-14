pub mod add_sub;
pub mod bitwise;
pub mod divrem;
pub mod lt;
pub mod mul;
pub mod sll;
pub mod sr;

pub use add_sub::*;
pub use bitwise::*;
pub use divrem::*;
pub use lt::*;
pub use mul::*;
use rand::Rng;
pub use sll::*;
pub use sr::*;

use serde::{Deserialize, Serialize};

use crate::runtime::Opcode;

/// A standard format for describing ALU operations that need to be proven.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AluEvent {
    /// The lookup id of the event.
    pub lookup_id: usize,

    /// The shard number, used for byte lookup table.
    pub shard: u32,

    /// The channel number, used for byte lookup table.
    pub channel: u32,

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

    pub sub_lookups: [usize; 6],
}

impl AluEvent {
    /// Creates a new `AluEvent`.
    pub fn new(shard: u32, channel: u32, clk: u32, opcode: Opcode, a: u32, b: u32, c: u32) -> Self {
        Self {
            lookup_id: 0,
            shard,
            channel,
            clk,
            opcode,
            a,
            b,
            c,
            sub_lookups: create_alu_lookups(),
        }
    }
}

pub fn create_alu_lookup_id() -> usize {
    let mut rng = rand::thread_rng();
    rng.gen()
}

pub fn create_alu_lookups() -> [usize; 6] {
    let mut rng = rand::thread_rng();
    [
        rng.gen(),
        rng.gen(),
        rng.gen(),
        rng.gen(),
        rng.gen(),
        rng.gen(),
    ]
}
