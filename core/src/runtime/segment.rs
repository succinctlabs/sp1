use std::collections::BTreeMap;

use super::program::Program;
use crate::alu::AluEvent;
use crate::bytes::ByteLookupEvent;
use crate::cpu::CpuEvent;
use crate::precompiles::sha256::ShaExtendEvent;
use crate::runtime::MemoryRecord;

#[derive(Default, Clone, Debug)]
pub struct Segment {
    /// The index of this segment in the program.
    pub index: u32,

    pub program: Program,

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

    /// A trace of the SLL and SLLI events.
    pub shift_left_events: Vec<AluEvent>,

    /// A trace of the SRL, SRLI, SRA, and SRAI events.
    pub shift_right_events: Vec<AluEvent>,

    /// A trace of the DIV, DIVU, REM, and REMU events.
    pub divrem_events: Vec<AluEvent>,

    /// A trace of the SLT, SLTI, SLTU, and SLTIU events.
    pub lt_events: Vec<AluEvent>,

    /// A trace of the byte lookups needed.
    pub byte_lookups: BTreeMap<ByteLookupEvent, usize>,

    /// TODO: cleanup
    pub sha_extend_events: Vec<ShaExtendEvent>,

    /// Information needed for global chips. This shouldn't really be in "Segment" but for
    /// legacy reasons, we keep this information in this struct for now.
    pub first_memory_record: Vec<(u32, MemoryRecord, u32)>,
    pub last_memory_record: Vec<(u32, MemoryRecord, u32)>,
    pub program_memory_record: Vec<(u32, MemoryRecord, u32)>,
}

impl Segment {
    pub fn add_byte_lookup_events(&mut self, blu_events: Vec<ByteLookupEvent>) {
        for blu_event in blu_events.iter() {
            self.byte_lookups
                .entry(*blu_event)
                .and_modify(|i| *i += 1)
                .or_insert(1);
        }
    }
}
