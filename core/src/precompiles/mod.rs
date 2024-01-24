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
        let record = self.rt.mr_core(addr, self.current_segment, self.clk);
        (record, record.value)
    }

    pub fn mr_slice(&mut self, addr: u32, len: usize) -> (Vec<MemoryReadRecord>, Vec<u32>) {
        let mut records = Vec::new();
        let mut values = Vec::new();
        for i in 0..len {
            let (record, value) = self.mr(addr + i as u32 * 4);
            records.push(record);
            values.push(value);
        }
        (records, values)
    }

    pub fn mw(&mut self, addr: u32, value: u32) -> MemoryWriteRecord {
        self.rt.mw_core(addr, value, self.current_segment, self.clk)
    }

    pub fn mw_slice(&mut self, addr: u32, values: &[u32]) -> Vec<MemoryWriteRecord> {
        let mut records = Vec::new();
        for i in 0..values.len() {
            let record = self.mw(addr + i as u32 * 4, values[i]);
            records.push(record);
        }
        records
    }

    /// Get the current value of a register, but doesn't use a memory record.
    /// This is generally unconstrained, so you must be careful using it.
    pub fn register_unsafe(&self, register: Register) -> u32 {
        self.rt.register(register)
    }

    pub fn word_unsafe(&self, addr: u32) -> u32 {
        self.rt.word(addr)
    }

    pub fn slice_unsafe(&self, addr: u32, len: usize) -> Vec<u32> {
        let mut values = Vec::new();
        for i in 0..len {
            values.push(self.rt.word(addr + i as u32 * 4));
        }
        values
    }
}
