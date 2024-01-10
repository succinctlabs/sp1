use std::collections::{BTreeMap, HashMap};

use super::program::Program;
use super::Opcode;
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

    /// A trace of the SLL and SLLI events.
    pub shift_left_events: Vec<AluEvent>,

    /// A trace of the SRL, SRLI, SRA, and SRAI events.
    pub shift_right_events: Vec<AluEvent>,

    /// A trace of the SLT, SLTI, SLTU, and SLTIU events.
    pub lt_events: Vec<AluEvent>,

    /// A trace of the byte lookups needed.
    pub byte_lookups: BTreeMap<ByteLookupEvent, usize>,
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

    pub fn add_alu_events(&mut self, alu_events: HashMap<Opcode, Vec<AluEvent>>) {
        for opcode in alu_events.keys() {
            match opcode {
                Opcode::ADD => {
                    self.add_events.extend_from_slice(&alu_events[opcode]);
                }
                Opcode::MUL | Opcode::MULH | Opcode::MULHU | Opcode::MULHSU => {
                    self.mul_events.extend_from_slice(&alu_events[opcode]);
                }
                Opcode::SUB => {
                    self.sub_events.extend_from_slice(&alu_events[opcode]);
                }
                Opcode::XOR | Opcode::OR | Opcode::AND => {
                    self.bitwise_events.extend_from_slice(&alu_events[opcode]);
                }
                Opcode::SLL => {
                    self.shift_left_events
                        .extend_from_slice(&alu_events[opcode]);
                }
                Opcode::SRL | Opcode::SRA => {
                    self.shift_right_events
                        .extend_from_slice(&alu_events[opcode]);
                }
                Opcode::SLT | Opcode::SLTU => {
                    self.lt_events.extend_from_slice(&alu_events[opcode]);
                }
                _ => {
                    panic!("Invalid opcode: {:?}", opcode);
                }
            }
        }
    }
}
