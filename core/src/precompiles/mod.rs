pub mod edwards;
pub mod sha256;

use crate::runtime::{Register, Runtime};
use crate::{cpu::MemoryReadRecord, cpu::MemoryWriteRecord, runtime::Segment};

/// A runtime for precompiles that is protected so that developers cannot arbitrarily modify the runtime.
pub struct PrecompileRuntime<'a> {
    current_segment: u32,
    pub clk: u32,

    rt: &'a mut Runtime, // Reference
}

impl<'a> PrecompileRuntime<'a> {
    pub fn new(runtime: &'a mut Runtime) -> Self {
        let current_segment = runtime.current_segment();
        let clk = runtime.clk;
        Self {
            current_segment,
            clk,
            rt: runtime,
        }
    }

    pub fn segment_mut(&mut self) -> &mut Segment {
        &mut self.rt.segment
    }

    pub fn mr(&mut self, addr: u32) -> (MemoryReadRecord, u32) {
        let value = self.rt.memory.entry(addr).or_insert(0);
        let (prev_segment, prev_timestamp) =
            self.rt.memory_access.get(&addr).cloned().unwrap_or((0, 0));

        self.rt
            .memory_access
            .insert(addr, (self.current_segment, self.clk));

        (
            MemoryReadRecord {
                value: *value,
                segment: self.current_segment,
                timestamp: self.clk,
                prev_segment,
                prev_timestamp,
            },
            *value,
        )
    }

    pub fn mw(&mut self, addr: u32, value: u32) -> MemoryWriteRecord {
        let prev_value = self.rt.memory.entry(addr).or_insert(0).clone();
        let (prev_segment, prev_timestamp) =
            self.rt.memory_access.get(&addr).cloned().unwrap_or((0, 0));
        self.rt
            .memory_access
            .insert(addr, (self.current_segment, self.clk));
        self.rt.memory.insert(addr, value);

        // TODO: can do some checks on the record clk and self.clk at this point
        MemoryWriteRecord {
            value,
            segment: self.current_segment,
            timestamp: self.clk,
            prev_value,
            prev_segment,
            prev_timestamp,
        }
    }

    /// Get the current value of a register, but doesn't use a memory record.
    /// This is generally unconstrained, so you must be careful using it.
    pub fn register_unsafe(&self, register: Register) -> u32 {
        self.rt.register(register)
    }

    pub fn word_unsafe(&self, addr: u32) -> u32 {
        self.rt.word(addr)
    }
}
