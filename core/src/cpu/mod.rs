use serde::{Deserialize, Serialize};

pub mod air;
pub mod witness;

/// The state of the CPU at a particular point in the program execution.
///
/// The CPU state is a snapshot of the CPU at a particular point in the program execution. It is
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cpu {
    /// The program timestamp.
    pub clk: u32,
    /// The program counter.
    pub pc: u32,
    /// The frame pointer.
    pub fp: u32,
    // The opcode of the current instruction.
    pub opcode: u8,
    /// The first argument of the current instruction.
    pub arg1: u32,
    /// The second argument of the current instruction.
    pub arg2: u32,
    /// The third argument of the current instruction.
    pub arg3: u32,
    /// The immediate vAlue of the current instruction (if any).
    pub imm: u32,
}
