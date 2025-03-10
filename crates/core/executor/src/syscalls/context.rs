use hashbrown::HashMap;

use crate::{
    events::{
        MemoryLocalEvent, MemoryReadRecord, MemoryWriteRecord, PrecompileEvent, SyscallEvent,
    },
    record::ExecutionRecord,
    Executor, ExecutorMode, Register,
};

use super::SyscallCode;

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
    /// The local memory access events for the syscall.
    pub local_memory_access: HashMap<u32, MemoryLocalEvent>,
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
            local_memory_access: HashMap::new(),
        }
    }

    /// Get a mutable reference to the execution record.
    pub fn record_mut(&mut self) -> &mut ExecutionRecord {
        &mut self.rt.record
    }

    #[inline]
    /// Add a precompile event to the execution record.
    pub fn add_precompile_event(
        &mut self,
        syscall_code: SyscallCode,
        syscall_event: SyscallEvent,
        event: PrecompileEvent,
    ) {
        if self.rt.executor_mode == ExecutorMode::Trace {
            self.record_mut().precompile_events.add_event(syscall_code, syscall_event, event);
        }
    }

    /// Get the current shard.
    #[must_use]
    pub fn current_shard(&self) -> u32 {
        self.rt.state.current_shard
    }

    /// Read a word from memory.
    ///
    /// `addr` must be a pointer to main memory, not a register.
    pub fn mr(&mut self, addr: u32) -> (MemoryReadRecord, u32) {
        let record =
            self.rt.mr(addr, self.current_shard, self.clk, Some(&mut self.local_memory_access));
        (record, record.value)
    }

    /// Read a slice of words from memory.
    ///
    /// `addr` must be a pointer to main memory, not a register.
    pub fn mr_slice(&mut self, addr: u32, len: usize) -> (Vec<MemoryReadRecord>, Vec<u32>) {
        let mut records = Vec::with_capacity(len);
        let mut values = Vec::with_capacity(len);
        for i in 0..len {
            let (record, value) = self.mr(addr + i as u32 * 4);
            records.push(record);
            values.push(value);
        }
        (records, values)
    }

    /// Write a word to memory.
    ///
    /// `addr` must be a pointer to main memory, not a register.
    pub fn mw(&mut self, addr: u32, value: u32) -> MemoryWriteRecord {
        self.rt.mw(addr, value, self.current_shard, self.clk, Some(&mut self.local_memory_access))
    }

    /// Write a slice of words to memory.
    pub fn mw_slice(&mut self, addr: u32, values: &[u32]) -> Vec<MemoryWriteRecord> {
        let mut records = Vec::with_capacity(values.len());
        for i in 0..values.len() {
            let record = self.mw(addr + i as u32 * 4, values[i]);
            records.push(record);
        }
        records
    }

    /// Read a register and record the memory access.
    pub fn rr_traced(&mut self, register: Register) -> (MemoryReadRecord, u32) {
        let record = self.rt.rr_traced(
            register,
            self.current_shard,
            self.clk,
            Some(&mut self.local_memory_access),
        );
        (record, record.value)
    }

    /// Write a register and record the memory access.
    pub fn rw_traced(&mut self, register: Register, value: u32) -> (MemoryWriteRecord, u32) {
        let record = self.rt.rw_traced(
            register,
            value,
            self.current_shard,
            self.clk,
            Some(&mut self.local_memory_access),
        );
        (record, record.value)
    }

    /// Postprocess the syscall.  Specifically will process the syscall's memory local events.
    pub fn postprocess(&mut self) -> Vec<MemoryLocalEvent> {
        let mut syscall_local_mem_events = Vec::new();

        if !self.rt.unconstrained {
            if self.rt.executor_mode == ExecutorMode::Trace {
                // Will need to transfer the existing memory local events in the executor to it's
                // record, and return all the syscall memory local events.  This is similar
                // to what `bump_record` does.
                for (addr, event) in self.local_memory_access.drain() {
                    let local_mem_access = self.rt.local_memory_access.remove(&addr);

                    if let Some(local_mem_access) = local_mem_access {
                        self.rt.record.cpu_local_memory_access.push(local_mem_access);
                    }

                    syscall_local_mem_events.push(event);
                }
            }
            if let Some(estimator) = &mut self.rt.record_estimator {
                let original_len = estimator.current_touched_compressed_addresses.len();
                // Remove addresses from the main set that were touched in the precompile.
                estimator.current_touched_compressed_addresses =
                    core::mem::take(&mut estimator.current_touched_compressed_addresses)
                        - &estimator.current_precompile_touched_compressed_addresses;
                // Add the number of addresses that were removed from the main set.
                estimator.current_local_mem +=
                    original_len - estimator.current_touched_compressed_addresses.len();
            }
        }

        syscall_local_mem_events
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
