use std::collections::{BTreeMap, HashMap, HashSet};

use elf::segment;

use super::instruction::Instruction;
use super::program::Program;
use crate::alu::AluEvent;
use crate::bytes::ByteLookupEvent;
use crate::cpu::CpuEvent;
use crate::memory::{MemOp, MemoryEvent};

#[derive(Default, Clone, Debug)]
pub struct SegmentMemoryEvent {
    pub event: MemoryEvent,
    pub connect_cpu: bool,
    pub unitialized_read: bool,
    pub last_touch: bool,
    pub send_to_next: bool,
}

#[derive(Default, Clone, Debug)]
pub struct SegmentMemory {
    writes: HashSet<u32>,
    reads: HashSet<u32>,
    events: Vec<SegmentMemoryEvent>,
    sealed: bool,
}

impl SegmentMemory {
    pub fn new() -> Self {
        Self {
            writes: HashSet::new(),
            reads: HashSet::new(),
            events: Vec::new(),
            sealed: false,
        }
    }

    pub fn get_events(&self) -> &[SegmentMemoryEvent] {
        &self.events
    }

    pub fn get_memory_events(&self) -> Vec<MemoryEvent> {
        self.events.iter().map(|event| event.event).collect()
    }

    // Add an event that should also be in the CPU table.
    pub fn add_event(&mut self, event: MemoryEvent) {
        assert_eq!(self.sealed, false, "Segment is already sealed");

        let unitialized_read = event.op == MemOp::Read
            && !self.writes.contains(&event.addr)
            && !self.reads.contains(&event.addr);

        match event.op {
            MemOp::Write => self.writes.insert(event.addr),
            MemOp::Read => self.reads.insert(event.addr),
        };

        if event.addr < 4094967048 {
            println!("event {:?}", event);
        }

        self.events.push(SegmentMemoryEvent {
            event,
            connect_cpu: true,
            unitialized_read,
            last_touch: false,   // Default initialization to false.
            send_to_next: false, // Default initialization to false.
        });
    }

    // Touch an addr that hasn't been touched before.
    // add_event should NOT be used after touch.
    pub fn touch_addr(&mut self, addr: u32, value: u32) {
        assert_eq!(self.sealed, false, "Segment is already sealed");
        assert!(!self.reads.contains(&addr) && !self.writes.contains(&addr));
        self.reads.insert(addr);
        self.events.push(SegmentMemoryEvent {
            event: MemoryEvent {
                clk: 0,
                addr,
                op: MemOp::Read,
                value,
            },
            connect_cpu: false,
            unitialized_read: true,
            last_touch: false, // Default initialization to false.
            send_to_next: false,
        });
    }

    pub fn finalize(&mut self, send_to_next: Vec<u32>) {
        assert_eq!(self.sealed, false, "Segment is already sealed");
        self.sealed = true;

        let mut touched = HashSet::new();
        let mut send_to_next_set: HashSet<u32> = HashSet::from_iter(send_to_next);
        for event in self.events.iter_mut().rev() {
            touched
                .insert(&event.event.addr)
                .then(|| event.last_touch = true);
            (event.last_touch && send_to_next_set.remove(&event.event.addr))
                .then(|| event.send_to_next = true);
        }
        assert_eq!(send_to_next_set.len(), 0, "send_to_next_local is not empty");
    }

    pub fn touched(&self, addr: u32) -> bool {
        self.writes.contains(&addr) || self.reads.contains(&addr)
    }

    pub fn unitialized_reads(&self) -> Vec<(u32, u32)> {
        self.events
            .iter()
            .filter(|event| event.unitialized_read)
            .map(|event| (event.event.addr, event.event.value))
            .collect()
    }
}
#[derive(Default, Clone, Debug)]
pub struct Segment {
    /// The index of this segment in the program.
    pub index: u32,

    pub program: Program,

    /// Keeps track of the memory events and additional information during execution of this segment.
    pub(crate) memory: SegmentMemory,

    /// All events that happen in this segment.

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

impl Segment {
    pub fn finalize_all(segments: &mut Vec<Segment>) {
        // Iterate through all the segments backwards.
        // [w1, r1, w2, r2, w5, r5] [w2, r2, r1] [w3, w4, r1, r1, r1, r2, r5]
        // reads
        // [], [r1], [r1, r2, r5]
        // synthetic reads
        // [], [r5], []

        let len = segments.len();

        // Iterate though segments backwards.
        for idx in (0..len).rev() {
            // For all segments but the last, we get the current segment and next segment.
            if idx < len - 1 {
                let (first_part, second_part) = segments.split_at_mut(idx + 1);
                let segment = &mut first_part[idx];
                let next_segment = &mut second_part[0];

                // Find all unitialized reads in the next_segment that are not touched in
                // the current segment and touch them.

                next_segment
                    .memory
                    .unitialized_reads()
                    .iter()
                    .for_each(|(addr, value)| {
                        (!segment.memory.touched(*addr)).then(|| {
                            segment.memory.touch_addr(*addr, *value);
                        });
                    });

                // Then finalize the current segment and pass in all addresses of the unitialized
                // reads from the next_segment.
                segment.memory.finalize(
                    next_segment
                        .memory
                        .unitialized_reads()
                        .iter()
                        .map(|(addr, _)| *addr)
                        .collect(),
                );
            } else {
                // For the last segment, we just finalize it since there are no next segments.
                let segment = &mut segments[idx];
                segment.memory.finalize(vec![]);
            }

            let segment = &mut segments[idx];
            println!(
                "unitialized reads {} {:?}",
                idx,
                segment.memory.unitialized_reads()
            );
        }
    }

    pub fn sanity_check(segments: &Vec<Segment>) {
        let len = segments.len();

        // Check that the "unitialized_reads" for the first segment is empty.
        let segment_0 = &segments[0];
        println!("touched {}", segment_0.memory.touched(8388604));
        println!(
            "segment_0.memory.unitialized_reads() = {:?}",
            segment_0.memory.unitialized_reads()
        );
        assert_eq!(
            segment_0.memory.unitialized_reads().len(),
            0,
            "segment_0.memory.unitialized_reads().len() != 0"
        );

        // Check that for all events in the last segment, send_to_next is false.
        let segment_last = &segments[len - 1];
        for event in segment_last.memory.events.iter() {
            assert_eq!(
                event.send_to_next, false,
                "event.send_to_next != false for event {:?} in last segment",
                event
            );
        }

        // Check for all segments except last that for segment[idx+1].memory.uninitialized_read
        // has exactly 1 corresponding event in segment[idx].memory.events where write_value=true.
        for idx in 0..len - 1 {
            let mut next_reads: HashSet<(u32, u32)> =
                HashSet::from_iter(segments[idx + 1].memory.unitialized_reads());
            for event in segments[idx].memory.events.iter() {
                if event.send_to_next {
                    next_reads.remove(&(event.event.addr, event.event.value));
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
