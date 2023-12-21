use std::collections::{BTreeMap, HashMap, HashSet};

use super::instruction::Instruction;
use crate::alu::AluEvent;
use crate::bytes::ByteLookupEvent;
use crate::cpu::CpuEvent;
use crate::memory::{MemOp, MemoryEvent};

#[derive(Default, Clone, Debug)]
pub struct SegmentMemoryEvent {
    pub event: MemoryEvent,
    pub first_read: bool,
    pub connect_clk: bool,
    pub write_value: bool,
}

#[derive(Default, Clone)]
pub struct SegmentMemory {
    writes: HashSet<u32>,
    events: Vec<SegmentMemoryEvent>,
    uninitialized_read: HashMap<u32, u32>,
    sealed: bool,
}

impl SegmentMemory {
    pub fn new() -> Self {
        Self {
            writes: HashSet::new(),
            events: Vec::new(),
            uninitialized_read: HashMap::new(),
            sealed: false,
        }
    }

    pub fn add_event(&mut self, event: MemoryEvent) {
        if self.sealed {
            panic!("Segment is already sealed");
        }
        let first_read = match event.op {
            MemOp::Write => {
                self.writes.insert(event.addr);
                false
            }
            MemOp::Read => {
                if self.writes.contains(&event.addr) {
                    false
                } else {
                    let exists = self.uninitialized_read.contains_key(&event.addr);
                    if exists {
                        // This means that it hasn't been written to yet, so should be same.
                        assert_eq!(
                            self.uninitialized_read[&event.addr], event.value,
                            "uninitialized_read[&event.addr] != event.value"
                        );
                        false
                    } else {
                        self.uninitialized_read.insert(event.addr, event.value);
                        true
                    }
                }
            }
        };
        self.events.push(SegmentMemoryEvent {
            event,
            first_read,
            connect_clk: true,
            write_value: false,
        });
    }

    pub fn add_ghost_event(&mut self, addr: u32, value: u32) {
        if self.sealed {
            panic!("Segment is already sealed");
        }
        assert!(
            !self.uninitialized_read.contains_key(&addr),
            "addr is already in self.uninitialized_read"
        );
        assert!(
            !self.writes.contains(&addr),
            "addr is already in self.writes"
        );
        self.uninitialized_read.insert(addr, value);
        self.events.push(SegmentMemoryEvent {
            event: MemoryEvent {
                clk: 0,
                addr,
                op: MemOp::Read,
                value,
            },
            first_read: true,
            connect_clk: false,
            write_value: false,
        });
    }

    pub fn finalize(&mut self, last_write_addr_inp: HashSet<u32>) {
        if self.sealed {
            panic!("Segment is already sealed");
        }
        self.sealed = true;
        let mut last_write_addr = last_write_addr_inp.clone();
        for event in self.events.iter_mut().rev() {
            if last_write_addr.contains(&event.event.addr) {
                event.write_value = true;
                last_write_addr.remove(&event.event.addr);
            }
        }
        assert_eq!(last_write_addr.len(), 0, "last_write_addr is not empty");
    }

    pub fn touched(&mut self) -> HashSet<u32> {
        self.writes
            .union(
                &self
                    .uninitialized_read
                    .keys()
                    .cloned()
                    .collect::<HashSet<_>>(),
            )
            .cloned()
            .collect()
    }

    pub fn first_reads(&mut self) -> HashSet<u32> {
        self.events
            .iter()
            .filter(|event| event.first_read)
            .map(|event| event.event.addr)
            .collect()
    }
}
#[derive(Default, Clone)]
pub struct Segment {
    pub program: Vec<Instruction>,
    pub memory: SegmentMemory,

    /// All events that happen in this segment.

    /// A trace of the CPU events which get emitted during execution.
    pub cpu_events: Vec<CpuEvent>,

    /// A trace of the memory events which get emitted during execution.
    pub memory_events: Vec<MemoryEvent>,

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

impl Segment {
    pub fn emit_memory(&mut self, event: &MemoryEvent) {
        self.memory_events.push(*event);
        self.memory.add_event(event.clone());
    }

    pub fn finalize_all(segments: &mut Vec<Segment>) {
        // Iterate through all the segments backwards.
        // [w1, r1, w2, r2, w5, r5] [w2, r2, r1] [w3, w4, r1, r1, r1, r2, r5]
        // reads
        // [], [r1], [r1, r2, r5]
        // synthetic reads
        // [], [r5], []

        let len = segments.len();

        for idx in (0..len).rev() {
            if idx < len - 1 {
                let (first_part, second_part) = segments.split_at_mut(idx + 1);
                let segment = &mut first_part[idx];
                let next_segment = &mut second_part[0];
                let unitialized_reads: HashSet<_> = next_segment
                    .memory
                    .uninitialized_read
                    .keys()
                    .cloned()
                    .collect();
                // Find all unitialized_reads from next segment that are not in segment.touched();
                unitialized_reads
                    .difference(&segment.memory.touched())
                    .for_each(|addr| {
                        segment
                            .memory
                            .add_ghost_event(*addr, next_segment.memory.uninitialized_read[addr])
                    });
                segment
                    .memory
                    .finalize(unitialized_reads.iter().cloned().collect());
            } else {
                let segment = &mut segments[idx];
                segment.memory.finalize(HashSet::new());
            }
        }
    }

    pub fn sanity_cehck(segments: &mut Vec<Segment>) {
        let len = segments.len();

        // Check that the "unitialized_reads" for the first segment is empty.
        let segment_0 = &segments[0];
        assert_eq!(
            segment_0.memory.uninitialized_read.len(),
            0,
            "segment_0.memory.uninitialized_read.len() != 0"
        );

        // Check that for all events in the last segment, write_value is false.
        let segment_last = &segments[len - 1];
        for event in segment_last.memory.events.iter() {
            assert_eq!(
                event.write_value, false,
                "event.write_value != false for event {:?} in last segment",
                event
            );
        }

        // Check for all segments except last that for segment[idx+1].memory.uninitialized_read
        // has exactly 1 corresponding event in segment[idx].memory.events where write_value=true.
        for idx in 0..len - 1 {
            let mut next_reads = segments[idx + 1].memory.uninitialized_read.clone();
            for event in segments[idx].memory.events.iter() {
                if event.write_value {
                    next_reads.remove(&event.event.addr);
                }
            }
            assert_eq!(
                next_reads.len(),
                0,
                "next_reads.len() != 0 for segment {}",
                idx + 1
            );
        }
    }
}
