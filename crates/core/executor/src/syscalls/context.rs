use crate::{
    events::{LookupId, MemoryReadRecord, MemoryWriteRecord},
    record::ExecutionRecord,
    Executor, Register,
};

/// A runtime for syscalls that is protected so that developers cannot arbitrarily modify the
/// runtime.
#[allow(dead_code)]
pub struct SyscallContext<'a, 'b: 'a> {
    /// The current shard.
    pub current_shard: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The next program counter.
    pub next_pc: u32,
    /// The exit code.
    pub exit_code: u32,
    /// The runtime.
    pub rt: &'a mut Executor<'b>,
    /// The syscall lookup id.
    pub syscall_lookup_id: LookupId,
}

impl<'a, 'b> SyscallContext<'a, 'b> {
    /// Create a new [`SyscallContext`].
    pub fn new(runtime: &'a mut Executor<'b>) -> Self {
        let current_shard = runtime.shard();
        let clk = runtime.state.clk;
        Self {
            current_shard,
            clk,
            next_pc: runtime.state.pc.wrapping_add(4),
            exit_code: 0,
            rt: runtime,
            syscall_lookup_id: LookupId::default(),
        }
    }

    /// Get a mutable reference to the execution record.
    pub fn record_mut(&mut self) -> &mut ExecutionRecord {
        &mut self.rt.record
    }

    /// Get the current shard.
    #[must_use]
    pub fn current_shard(&self) -> u32 {
        self.rt.state.current_shard
    }

    /// Get the current channel.
    #[must_use]
    pub fn current_channel(&self) -> u8 {
        self.rt.state.channel
    }

    /// Read a word from memory.
    pub fn mr(&mut self, addr: u32) -> (MemoryReadRecord, u32) {
        let record = self.rt.mr(addr, self.current_shard, self.clk);
        (record, record.value)
    }

    /// Read a slice of words from memory.
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

    /// Write a word to memory.
    pub fn mw(&mut self, addr: u32, value: u32) -> MemoryWriteRecord {
        self.rt.mw(addr, value, self.current_shard, self.clk)
    }

    /// Write a slice of words to memory.
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
    #[must_use]
    pub fn register_unsafe(&mut self, register: Register) -> u32 {
        self.rt.register(register)
    }

    /// Get the current value of a byte, but doesn't use a memory record.
    #[must_use]
    pub fn byte_unsafe(&mut self, addr: u32) -> u8 {
        self.rt.byte(addr)
    }

    /// Get the current value of a word, but doesn't use a memory record.
    #[must_use]
    pub fn word_unsafe(&mut self, addr: u32) -> u32 {
        self.rt.word(addr)
    }

    /// Get a slice of words, but doesn't use a memory record.
    #[must_use]
    pub fn slice_unsafe(&mut self, addr: u32, len: usize) -> Vec<u32> {
        let mut values = Vec::new();
        for i in 0..len {
            values.push(self.rt.word(addr + i as u32 * 4));
        }
        values
    }

    /// Set the next program counter.
    pub fn set_next_pc(&mut self, next_pc: u32) {
        self.next_pc = next_pc;
    }

    /// Set the exit code.
    pub fn set_exit_code(&mut self, exit_code: u32) {
        self.exit_code = exit_code;
    }
}
