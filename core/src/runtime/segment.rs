use std::collections::BTreeMap;

use super::program::Program;
use crate::alu::AluEvent;
use crate::bytes::ByteLookupEvent;
use crate::cpu::CpuEvent;
use crate::runtime::MemoryRecord;

#[derive(Default, Clone, Debug)]
pub struct Segment {
    /// The index of this segment in the program.
    pub index: u32,

    pub program: Program,

    /// The first memory record for each address.
    pub first_memory_record: Vec<(u32, MemoryRecord)>,

    /// The last memory record for each address.
    pub last_memory_record: Vec<(u32, MemoryRecord)>,

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

    /// (clk, w_ptr)
    pub sha_events: Vec<(
        u32,
        u32,
        Vec<u32>,
        Vec<MemoryRecord>,
        Vec<MemoryRecord>,
        Vec<MemoryRecord>,
        Vec<MemoryRecord>,
        Vec<MemoryRecord>,
    )>,
}
