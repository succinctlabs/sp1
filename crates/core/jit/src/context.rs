use crate::{debug, MemValue, RiscRegister, TraceChunkHeader};
use memmap2::{MmapMut, MmapOptions};
use std::{collections::VecDeque, io, os::fd::RawFd, ptr::NonNull, sync::mpsc};

pub trait SyscallContext {
    /// Read a value from a register.
    fn rr(&self, reg: RiscRegister) -> u64;
    /// Read a value from memory.
    fn mr(&mut self, addr: u64) -> u64;
    /// Write a value to memory.
    fn mw(&mut self, addr: u64, val: u64);
    /// Read a slice of values from memory.
    fn mr_slice(&mut self, addr: u64, len: usize) -> impl IntoIterator<Item = &u64>;
    /// Read a slice of values from memory, without updating the memory clock
    /// Note that it still traces the access when tracing is enabled.
    fn mr_slice_unsafe(&mut self, addr: u64, len: usize) -> impl IntoIterator<Item = &u64>;
    /// Read a slice of values from memory, without updating the memory clock or tracing the access.
    fn mr_slice_no_trace(&mut self, addr: u64, len: usize) -> impl IntoIterator<Item = &u64>;
    /// Write a slice of values to memory.
    fn mw_slice(&mut self, addr: u64, vals: &[u64]);
    /// Get the input buffer
    fn input_buffer(&mut self) -> &mut VecDeque<Vec<u8>>;
    /// Get the public values stream.
    fn public_values_stream(&mut self) -> &mut Vec<u8>;
    /// Enter the unconstrained context.
    fn enter_unconstrained(&mut self) -> io::Result<()>;
    /// Exit the unconstrained context.
    fn exit_unconstrained(&mut self);
    /// Trace a hint.
    fn trace_hint(&mut self, addr: u64, value: Vec<u8>);
    /// Trace a dummy value.
    fn trace_value(&mut self, value: u64);
    /// Write a hint to memory, which is like setting uninitialized memory to a nonzero value
    /// The clk will be set to 0, just like for uninitialized memory.
    fn mw_hint(&mut self, addr: u64, val: u64);
    /// Used for precompiles that access memory, that need to bump the clk.
    /// This increment is local to the precompile, and does not affect the number of cycles
    /// the precompile itself takes up.
    fn bump_memory_clk(&mut self);
    /// Set the exit code of the program.
    fn set_exit_code(&mut self, exit_code: u32);
    /// Returns if were in unconstrained mode.
    fn is_unconstrained(&self) -> bool;
    /// Get the global clock (total cycles executed).
    fn global_clk(&self) -> u64;

    /// Start tracking cycles for a label (profiling only).
    /// Records the current `global_clk` as the start time.
    /// Returns the nesting depth (0 for top-level, 1 for first nested, etc.).
    #[cfg(feature = "profiling")]
    fn cycle_tracker_start(&mut self, name: &str) -> u32;

    /// End tracking cycles for a label (profiling only).
    /// Returns (cycles_elapsed, depth) or None if no matching start.
    #[cfg(feature = "profiling")]
    fn cycle_tracker_end(&mut self, name: &str) -> Option<(u64, u32)>;

    /// End tracking cycles for a label and accumulate to report totals (profiling only).
    /// This is for "report" variants that should be included in ExecutionReport.
    /// Returns (cycles_elapsed, depth) or None if no matching start.
    #[cfg(feature = "profiling")]
    fn cycle_tracker_report_end(&mut self, name: &str) -> Option<(u64, u32)>;
}

impl SyscallContext for JitContext {
    #[inline]
    fn bump_memory_clk(&mut self) {
        self.clk += 1;
    }

    fn rr(&self, reg: RiscRegister) -> u64 {
        self.registers[reg as usize]
    }

    fn mr(&mut self, addr: u64) -> u64 {
        unsafe { ContextMemory::new(self).mr(addr) }
    }

    fn mw(&mut self, addr: u64, val: u64) {
        unsafe { ContextMemory::new(self).mw(addr, val) };
    }

    fn mr_slice(&mut self, addr: u64, len: usize) -> impl IntoIterator<Item = &u64> {
        debug_assert!(addr.is_multiple_of(8), "Address {addr} is not aligned to 8");

        // Convert the byte address to the word address.
        let word_address = addr / 8;

        let ptr = self.memory.as_ptr() as *mut MemValue;
        let ptr = unsafe { ptr.add(word_address as usize) };

        // SAFETY: The pointer is valid to write to, as it was aligned by us during allocation.
        // See [JitFunction::new] for more details.
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

        if self.tracing() {
            unsafe {
                self.trace_mem_access(slice);

                // Bump the clk on the all current entries.
                for (i, entry) in slice.iter().enumerate() {
                    let new_entry = MemValue { value: entry.value, clk: self.clk };
                    std::ptr::write(ptr.add(i), new_entry)
                }
            }
        }

        slice.iter().map(|val| &val.value)
    }

    fn mr_slice_no_trace(&mut self, addr: u64, len: usize) -> impl IntoIterator<Item = &u64> {
        debug_assert!(addr.is_multiple_of(8), "Address {addr} is not aligned to 8");

        // Convert the byte address to the word address.
        let word_address = addr / 8;

        let ptr = self.memory.as_ptr() as *mut MemValue;
        let ptr = unsafe { ptr.add(word_address as usize) };

        // SAFETY: The pointer is valid to write to, as it was aligned by us during allocation.
        // See [JitFunction::new] for more details.
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

        slice.iter().map(|val| &val.value)
    }

    fn mr_slice_unsafe(&mut self, addr: u64, len: usize) -> impl IntoIterator<Item = &u64> {
        debug_assert!(addr.is_multiple_of(8), "Address {addr} is not aligned to 8");

        // Convert the byte address to the word address.
        let word_address = addr / 8;

        let ptr = self.memory.as_ptr() as *mut MemValue;
        let ptr = unsafe { ptr.add(word_address as usize) };

        // SAFETY: The pointer is valid to write to, as it was aligned by us during allocation.
        // See [JitFunction::new] for more details.
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

        if self.tracing() {
            unsafe {
                self.trace_mem_access(slice);
            }
        }

        slice.iter().map(|val| &val.value)
    }

    fn mw_slice(&mut self, addr: u64, vals: &[u64]) {
        unsafe { ContextMemory::new(self).mw_slice(addr, vals) };
    }

    fn input_buffer(&mut self) -> &mut VecDeque<Vec<u8>> {
        unsafe { self.input_buffer() }
    }

    fn public_values_stream(&mut self) -> &mut Vec<u8> {
        unsafe { self.public_values_stream() }
    }

    fn enter_unconstrained(&mut self) -> io::Result<()> {
        self.enter_unconstrained()
    }

    fn exit_unconstrained(&mut self) {
        self.exit_unconstrained()
    }

    fn trace_hint(&mut self, addr: u64, value: Vec<u8>) {
        if self.tracing {
            unsafe { self.trace_hint(addr, value) };
        }
    }

    fn trace_value(&mut self, value: u64) {
        if self.tracing {
            unsafe {
                // u64::MAX is used as the clock, so it should likely be distinguished
                // from memory values.
                self.trace_mem_access(&[MemValue { clk: u64::MAX, value }]);
            }
        }
    }

    fn mw_hint(&mut self, addr: u64, val: u64) {
        unsafe { ContextMemory::new(self).mw_hint(addr, val) };
    }

    fn set_exit_code(&mut self, exit_code: u32) {
        self.exit_code = exit_code;
    }

    fn is_unconstrained(&self) -> bool {
        self.is_unconstrained == 1
    }

    fn global_clk(&self) -> u64 {
        self.global_clk
    }

    #[cfg(feature = "profiling")]
    fn cycle_tracker_start(&mut self, _name: &str) -> u32 {
        // JitContext is not used when profiling is enabled (portable executor is used instead).
        // This is a no-op implementation for trait completeness.
        0
    }

    #[cfg(feature = "profiling")]
    fn cycle_tracker_end(&mut self, _name: &str) -> Option<(u64, u32)> {
        // JitContext is not used when profiling is enabled (portable executor is used instead).
        // This is a no-op implementation for trait completeness.
        None
    }

    #[cfg(feature = "profiling")]
    fn cycle_tracker_report_end(&mut self, _name: &str) -> Option<(u64, u32)> {
        // JitContext is not used when profiling is enabled (portable executor is used instead).
        // This is a no-op implementation for trait completeness.
        None
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct JitContext {
    /// The current program counter
    pub pc: u64,
    /// The number of cycles executed.
    pub clk: u64,
    /// The number of cycles executed.
    pub global_clk: u64,
    /// This context is in unconstrainted mode.
    /// 1 if unconstrained, 0 otherwise.
    pub is_unconstrained: u64,
    /// Mapping from (pc - pc_base) / 4 => absolute address of the instruction.
    pub(crate) jump_table: NonNull<*const u8>,
    /// The pointer to the program memory.
    pub(crate) memory: NonNull<u8>,
    /// The pointer to the trace buffer.
    pub(crate) trace_buf: NonNull<u8>,
    /// The registers to start the execution with,
    /// these are loaded into real native registers at the start of execution.
    pub(crate) registers: [u64; 32],
    /// The input buffer to the program.
    pub(crate) input_buffer: NonNull<VecDeque<Vec<u8>>>,
    /// A stream of public values from the program (global to entire program).
    pub(crate) public_values_stream: NonNull<Vec<u8>>,
    /// The hints read by the program, with thier corresponding start address.
    pub(crate) hints: NonNull<Vec<(u64, Vec<u8>)>>,
    /// The memory file descriptor, this is used to create the COW memory at runtime.
    pub(crate) memory_fd: RawFd,
    /// The unconstrained context, this is used to create the COW memory at runtime.
    pub(crate) maybe_unconstrained: Option<UnconstrainedCtx>,
    /// Whether the JIT is tracing.
    pub(crate) tracing: bool,
    /// Whether the JIT is sending debug state every instruction.
    pub(crate) debug_sender: Option<mpsc::SyncSender<Option<debug::State>>>,
    /// The exit code of the program.
    pub(crate) exit_code: u32,
}

impl JitContext {
    /// # Safety
    /// - todo
    pub unsafe fn trace_mem_access(&self, reads: &[MemValue]) {
        // QUESTIONABLE: I think as long as Self is not `Sync` youre mostly fine, but its unclear,
        // how to actually call this method safe without taking a `&mut self`.

        // Read the current num reads from the trace buf.
        let raw = self.trace_buf.as_ptr();
        let num_reads_offset = std::mem::offset_of!(TraceChunkHeader, num_mem_reads);
        let num_reads_ptr = raw.add(num_reads_offset);
        let num_reads = std::ptr::read_unaligned(num_reads_ptr as *mut u64);

        // Write the new num reads to the trace buf.
        let new_num_reads = num_reads + reads.len() as u64;
        std::ptr::write_unaligned(num_reads_ptr as *mut u64, new_num_reads);

        // Write the new reads to the trace buf.
        let reads_start = std::mem::size_of::<TraceChunkHeader>();
        let tail_ptr = raw.add(reads_start) as *mut MemValue;
        let tail_ptr = tail_ptr.add(num_reads as usize);

        for (i, read) in reads.iter().enumerate() {
            std::ptr::write(tail_ptr.add(i), *read);
        }
    }

    /// Enter the unconstrained context, this will create a COW memory map of the memory file
    /// descriptor.
    pub fn enter_unconstrained(&mut self) -> io::Result<()> {
        // SAFETY: The memory is allocated by the [JitFunction] and is valid, not aliased, and has
        // enough space for the alignment.
        let mut cow_memory =
            unsafe { MmapOptions::new().no_reserve_swap().map_copy(self.memory_fd)? };
        let cow_memory_ptr = cow_memory.as_mut_ptr();

        // Align the ptr to u32.
        // SAFETY: u8 has the minimum alignment, so any larger alignment will be a multiple of this.
        let align_offset = cow_memory_ptr.align_offset(std::mem::align_of::<u64>());
        let cow_memory_ptr = unsafe { cow_memory_ptr.add(align_offset) };

        // Preserve the current state of the JIT context.
        self.maybe_unconstrained = Some(UnconstrainedCtx {
            cow_memory,
            actual_memory_ptr: self.memory,
            pc: self.pc,
            clk: self.clk,
            global_clk: self.global_clk,
            registers: self.registers,
        });

        // Bump the PC to the next instruction.
        self.pc = self.pc.wrapping_add(4);

        // Set the memory pointer used by the JIT as the COW memory.
        //
        // SAFETY: [memmap2] does not return a null pointer.
        self.memory = unsafe { NonNull::new_unchecked(cow_memory_ptr) };

        // Set the is_unconstrained flag to 1.
        self.is_unconstrained = 1;

        Ok(())
    }

    /// Exit the unconstrained context, this will restore the original memory map.
    pub fn exit_unconstrained(&mut self) {
        let unconstrained = std::mem::take(&mut self.maybe_unconstrained)
            .expect("Exit unconstrained called but not context is present, this is a bug.");

        self.memory = unconstrained.actual_memory_ptr;
        self.pc = unconstrained.pc;
        self.registers = unconstrained.registers;
        self.clk = unconstrained.clk;
        self.is_unconstrained = 0;
    }

    /// Indicate that the program has read a hint.
    ///
    /// This is used to store the hints read by the program.
    ///
    /// # Safety
    /// - The address must be aligned to 8 bytes.
    /// - The hints pointer must not be mutably aliased.
    pub unsafe fn trace_hint(&mut self, addr: u64, value: Vec<u8>) {
        debug_assert!(addr.is_multiple_of(8), "Address {addr} is not aligned to 8");
        self.hints.as_mut().push((addr, value));
    }

    /// Obtain a mutable view of the emulated memory.
    pub const fn memory(&mut self) -> ContextMemory<'_> {
        unsafe { ContextMemory::new(self) }
    }

    /// # Safety
    /// - The input buffer must be non null and valid to read from.
    pub const unsafe fn input_buffer(&mut self) -> &mut VecDeque<Vec<u8>> {
        self.input_buffer.as_mut()
    }

    /// # Safety
    /// - The public values stream must be non null and valid to read from.
    pub const unsafe fn public_values_stream(&mut self) -> &mut Vec<u8> {
        self.public_values_stream.as_mut()
    }

    /// Obtain a view of the registers.
    pub const fn registers(&self) -> &[u64; 32] {
        &self.registers
    }

    pub const fn rw(&mut self, reg: RiscRegister, val: u64) {
        self.registers[reg as usize] = val;
    }

    pub const fn rr(&self, reg: RiscRegister) -> u64 {
        self.registers[reg as usize]
    }

    #[inline]
    pub const fn tracing(&self) -> bool {
        self.tracing
    }
}

/// The saved context of the JIT runtime, when entering the unconstrained context.
#[derive(Debug)]
pub struct UnconstrainedCtx {
    // An COW version of the memory.
    pub cow_memory: MmapMut,
    // The pointer to the actual memory.
    pub actual_memory_ptr: NonNull<u8>,
    // The program counter.
    pub pc: u64,
    // The clock.
    pub clk: u64,
    // The clock.
    pub global_clk: u64,
    // The registers.
    pub registers: [u64; 32],
}

/// A type representing the memory of the emulated program.
///
/// This is used to read and write to the memory in precompile impls.
pub struct ContextMemory<'a> {
    ctx: &'a mut JitContext,
}

impl<'a> ContextMemory<'a> {
    /// Create a new memory view.
    ///
    /// This type takes in a mutable refrence with a lifetime to avoid aliasing the underlying
    /// memory region.
    ///
    /// # Safety
    /// - The memory is valid for the lifetime of this type.
    /// - The memory should be aligned to 8 bytes.
    /// - The memory should be valid to read from and write to.
    /// - The memory should be the expected size.
    const unsafe fn new(ctx: &'a mut JitContext) -> Self {
        Self { ctx }
    }

    #[inline]
    pub const fn tracing(&self) -> bool {
        self.ctx.tracing()
    }

    /// Read a u64 from the memory.
    pub fn mr(&self, addr: u64) -> u64 {
        debug_assert!(addr.is_multiple_of(8), "Address {addr} is not aligned to 8");
        // Convert the byte address to the word address.
        let word_address = addr / 8;

        let ptr = self.ctx.memory.as_ptr() as *mut MemValue;
        let ptr = unsafe { ptr.add(word_address as usize) };

        // SAFETY: The pointer is valid to read from, as it was aligned by us during allocation.
        // See [JitFunction::new] for more details.
        let entry = unsafe { std::ptr::read(ptr) };

        if self.tracing() {
            unsafe {
                self.ctx.trace_mem_access(&[entry]);

                // Bump the clk
                let new_entry = MemValue { value: entry.value, clk: self.ctx.clk };
                std::ptr::write(ptr, new_entry);
            }
        }

        entry.value
    }

    /// Write a u64 to the memory.
    pub fn mw(&mut self, addr: u64, val: u64) {
        debug_assert!(addr.is_multiple_of(8), "Address {addr} is not aligned to 8");

        // Convert the byte address to the word address.
        let word_address = addr / 8;

        let ptr = self.ctx.memory.as_ptr() as *mut MemValue;
        let ptr = unsafe { ptr.add(word_address as usize) };

        // Bump the clk and insert the new value.
        let value = MemValue { value: val, clk: self.ctx.clk };

        // Trace the current entry.
        if self.tracing() {
            unsafe {
                // Trace the current entry, the clock is bumped in the subsequent write.
                let current_entry = std::ptr::read(ptr);
                self.ctx.trace_mem_access(&[current_entry, value]);
            }
        }

        // SAFETY: The pointer is valid to write to, as it was aligned by us during allocation.
        // See [JitFunction::new] for more details.
        unsafe { std::ptr::write(ptr, value) };
    }

    /// Read a slice of u64 from the memory.
    pub fn mr_slice(&self, addr: u64, len: usize) -> impl IntoIterator<Item = &u64> + Clone {
        debug_assert!(addr.is_multiple_of(8), "Address {addr} is not aligned to 8");

        // Convert the byte address to the word address.
        let word_address = addr / 8;

        let ptr = self.ctx.memory.as_ptr() as *mut MemValue;
        let ptr = unsafe { ptr.add(word_address as usize) };

        // SAFETY: The pointer is valid to write to, as it was aligned by us during allocation.
        // See [JitFunction::new] for more details.
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

        if self.tracing() {
            unsafe {
                self.ctx.trace_mem_access(slice);

                // Bump the clk on the all current entries.
                for (i, entry) in slice.iter().enumerate() {
                    let new_entry = MemValue { value: entry.value, clk: self.ctx.clk };
                    std::ptr::write(ptr.add(i), new_entry)
                }
            }
        }

        slice.iter().map(|val| &val.value)
    }

    // Read a slice from memory, without bumping the clk.
    pub fn mr_slice_unsafe(&self, addr: u64, len: usize) -> impl IntoIterator<Item = &u64> + Clone {
        debug_assert!(addr.is_multiple_of(8), "Address {addr} is not aligned to 8");

        // Convert the byte address to the word address.
        let word_address = addr / 8;

        let ptr = self.ctx.memory.as_ptr() as *mut MemValue;
        let ptr = unsafe { ptr.add(word_address as usize) };

        // SAFETY: The pointer is valid to write to, as it was aligned by us during allocation.
        // See [JitFunction::new] for more details.
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

        if self.tracing() {
            unsafe {
                self.ctx.trace_mem_access(slice);
            }
        }

        slice.iter().map(|val| &val.value)
    }

    /// Write a slice of u64 to the memory.
    pub fn mw_slice(&mut self, addr: u64, vals: &[u64]) {
        debug_assert!(addr.is_multiple_of(8), "Address {addr} is not aligned to 8");

        // Convert the byte address to the word address.
        let word_address = addr / 8;

        let ptr = self.ctx.memory.as_ptr() as *mut MemValue;
        let ptr = unsafe { ptr.add(word_address as usize) };

        // Bump the clk and insert the new values.
        let values = vals.iter().map(|val| MemValue { value: *val, clk: self.ctx.clk });

        // Trace the current entries.

        if self.tracing() {
            unsafe {
                let current_entries = std::slice::from_raw_parts(ptr, vals.len());

                for (curr, new) in current_entries.iter().zip(values.clone()) {
                    self.ctx.trace_mem_access(&[*curr, new]);
                }
            }
        }

        for (i, val) in values.enumerate() {
            unsafe { std::ptr::write(ptr.add(i), val) };
        }
    }

    // Read a slice from memory, without bumping the clk.
    pub fn mr_slice_no_trace(
        &self,
        addr: u64,
        len: usize,
    ) -> impl IntoIterator<Item = &u64> + Clone {
        debug_assert!(addr.is_multiple_of(8), "Address {addr} is not aligned to 8");

        // Convert the byte address to the word address.
        let word_address = addr / 8;

        let ptr = self.ctx.memory.as_ptr() as *mut MemValue;
        let ptr = unsafe { ptr.add(word_address as usize) };

        // SAFETY: The pointer is valid to write to, as it was aligned by us during allocation.
        // See [JitFunction::new] for more details.
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

        slice.iter().map(|val| &val.value)
    }

    /// Write a u64 to memory, without tracing and sets the clk in the entry to 0.
    pub fn mw_hint(&mut self, addr: u64, val: u64) {
        let words = addr / 8;

        let ptr = self.ctx.memory.as_ptr() as *mut MemValue;
        let ptr = unsafe { ptr.add(words as usize) };

        let new_entry = MemValue { value: val, clk: 0 };
        unsafe { std::ptr::write(ptr, new_entry) };
    }
}
