pub mod edwards;
pub mod sha256;

use crate::runtime::Register;
use crate::{cpu::MemoryReadRecord, cpu::MemoryRecord, cpu::MemoryWriteRecord, runtime::Segment};
use nohash_hasher::BuildNoHashHasher;
use std::collections::HashMap;

/// A runtime for precompiles that is protected so that developers cannot arbitrarily modify the runtime.
pub struct PrecompileRuntime<'a> {
    pub segment_number: u32,
    pub clk: u32,

    pub memory: &'a mut HashMap<u32, u32, BuildNoHashHasher<u32>>, // Reference
    pub memory_access: &'a mut HashMap<u32, (u32, u32), BuildNoHashHasher<u32>>, // Reference
    pub segment: &'a mut Segment,                                  // Reference

    pub peeks: HashMap<u32, MemoryRecord, BuildNoHashHasher<u32>>,
}

impl<'a> PrecompileRuntime<'a> {
    pub fn new(
        segment_number: u32,
        clk: u32,
        memory: &'a mut HashMap<u32, u32, BuildNoHashHasher<u32>>,
        memory_access: &'a mut HashMap<u32, (u32, u32), BuildNoHashHasher<u32>>,
        segment: &'a mut Segment,
    ) -> Self {
        Self {
            segment_number,
            clk,
            memory,
            memory_access,
            segment,
            peeks: HashMap::default(),
        }
    }

    pub fn mr(&mut self, addr: u32) -> (MemoryReadRecord, u32) {
        let value = self.memory.entry(addr).or_insert(0);
        let (prev_segment, prev_timestamp) =
            self.memory_access.get(&addr).cloned().unwrap_or((0, 0));

        self.memory_access
            .insert(addr, (self.segment_number, self.clk));

        (
            MemoryReadRecord {
                value: *value,
                segment: self.segment_number,
                timestamp: self.clk,
                prev_segment,
                prev_timestamp,
            },
            *value,
        )
    }

    pub fn peek(&mut self, addr: u32) -> u32 {
        // All peeks must be accompanied by a write.
        let value = self.memory.entry(addr).or_insert(0);
        let (prev_segment, prev_timestamp) =
            self.memory_access.get(&addr).cloned().unwrap_or((0, 0));

        let record = MemoryRecord {
            value: *value,
            segment: prev_segment,
            timestamp: prev_timestamp,
        };
        self.peeks.insert(addr, record.clone());
        *value
    }

    pub fn mw(&mut self, addr: u32, value: u32) -> MemoryWriteRecord {
        // All peeks must be accompanied by a write.
        let prev_value = self.memory.entry(addr).or_insert(0);
        let (prev_segment, prev_timestamp) =
            self.memory_access.get(&addr).cloned().unwrap_or((0, 0));

        let record = MemoryRecord {
            value: *prev_value,
            segment: prev_segment,
            timestamp: prev_timestamp,
        };
        // // All writes must be accompanied by a peek.
        // let record = self
        //     .peeks
        //     .remove(&addr)
        //     .expect("A write must be peeked before");
        self.memory_access
            .insert(addr, (self.segment_number, self.clk));
        self.memory.insert(addr, value);
        // TODO: can do some checks on the record clk and self.clk at this point
        MemoryWriteRecord {
            value,
            segment: self.segment_number,
            timestamp: self.clk,
            prev_value: record.value,
            prev_segment: record.segment,
            prev_timestamp: record.timestamp,
        }
    }

    /// TODO: this should not be used, it is a hack!
    /// Get the current value of a register.
    pub fn register(&self, register: Register) -> u32 {
        let addr = register as u32;
        match self.memory.get(&addr) {
            Some(value) => *value,
            None => 0,
        }
    }
}
