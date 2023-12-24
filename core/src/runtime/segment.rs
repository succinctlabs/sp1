use std::collections::BTreeMap;

use super::program::Program;
use crate::alu::AluEvent;
use crate::bytes::ByteLookupEvent;
use crate::cpu::CpuEvent;

#[derive(Default, Clone, Debug)]
pub struct Segment {
    /// The index of this segment in the program.
    pub index: u32,

    pub program: Program,

    /// All events that happen in this segment.
    pub memory_access: Vec<(u32, u32, u32, u32)>,

    /// A trace of the CPU events which get emitted during execution.
    pub cpu_events: Vec<CpuEvent>,

    /// A trace of the ADD, and ADDI events.
    pub add_events: Vec<AluEvent>,

    /// A trace of the MUL events.
    pub mul_events: Vec<AluEvent>,

    /// A trace of the SUB events.
    pub sub_events: Vec<AluEvent>,

    /// A trace of the XOR, XORI, OR, ORI, AND, and ANDI events.
    pub bitwise_events: Vec<AluEvent>,

    /// A trace of the SLL, SLLI, SRL, SRLI, SRA, and SRAI events.
    pub shift_events: Vec<AluEvent>,

    /// A trace of the SLT, SLTI, SLTU, and SLTIU events.
    pub lt_events: Vec<AluEvent>,

    /// A trace of the byte lookups needed.
    pub byte_lookups: BTreeMap<ByteLookupEvent, usize>,
}
