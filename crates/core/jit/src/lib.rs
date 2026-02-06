#![cfg_attr(not(target_os = "linux"), allow(unused))]

#[cfg(not(target_endian = "little"))]
compile_error!("This crate is only supported on little endian targets.");

pub mod backends;
pub mod context;
pub mod debug;
pub mod instructions;
mod macros;
pub mod risc;

use dynasmrt::ExecutableBuffer;
use hashbrown::HashMap;
use memmap2::{MmapMut, MmapOptions};
use std::{
    collections::VecDeque,
    io,
    os::fd::AsRawFd,
    ptr::NonNull,
    sync::{mpsc, Arc},
};

pub use backends::*;
pub use context::*;
pub use instructions::*;
pub use risc::*;

/// A function that accepts the memory pointer.
pub type ExternFn = extern "C" fn(*mut JitContext);

pub type EcallHandler = extern "C" fn(*mut JitContext) -> u64;

/// A debugging utility to inspect registers
pub type DebugFn = extern "C" fn(u64);

/// A transpiler for risc32 instructions.
///
/// This trait is implemented for each target architecture supported by the JIT transpiler.
///
/// The transpiler is responsible for translating the risc32 instructions into the target
/// architecture's instruction set.
///
/// This transpiler should generate an entrypoint of the form: [`fn(*mut JitContext)`]
///
/// For each instruction, you will typically want to call [`SP1RiscvTranspiler::start_instr`]
/// before transpiling the instruction. This maps a "riscv instruction index" to some physical
/// native address, as there are multiple native instructions per riscv instruction.
///
/// You will also likely want to call [`SP1RiscvTranspiler::bump_clk`] to increment the clock
/// counter, and [`SP1RiscvTranspiler::set_pc`] to set the PC.
///
/// # Note
/// Some instructions will directly modify the PC, such as [`SP1RiscvTranspiler::jal`] and
/// [`SP1RiscvTranspiler::jalr`], and all the branch instructions, for these instructions, you would
/// not want to call [`SP1RiscvTranspiler::set_pc`] as it will be called for you.
///
///
/// ```rust,no_run,ignore
/// pub fn add_program() {
///     let mut transpiler = SP1RiscvTranspiler::new(program_size, memory_size, trace_buf_size, 100, 100).unwrap();
///      
///     // Transpile the first instruction.
///     transpiler.start_instr();
///     transpiler.add(RiscOperand::Reg(RiscRegister::A), RiscOperand::Reg(RiscRegister::B), RiscRegister::C);
///     transpiler.end_instr();
///     
///     // Transpile the second instruction.
///     transpiler.start_instr();
///
///     transpiler.add(RiscOperand::Reg(RiscRegister::A), RiscOperand::Reg(RiscRegister::B), RiscRegister::C);
///     transpiler.end_instr();
///     
///     let mut func = transpiler.finalize();
///
///     // Call the function.
///     let traces = func.call();
///
///     // do stuff with the traces.
/// }
/// ```
pub trait RiscvTranspiler:
    TraceCollector
    + ComputeInstructions
    + ControlFlowInstructions
    + MemoryInstructions
    + SystemInstructions
    + Sized
{
    /// Create a new transpiler.
    ///
    /// The program is used for the jump-table and is not a hard limit on the size of the program.
    /// The memory size is the exact amount that will be allocated for the program.
    fn new(
        program_size: usize,
        memory_size: usize,
        max_trace_size: u64,
        pc_start: u64,
        pc_base: u64,
        clk_bump: u64,
    ) -> Result<Self, std::io::Error>;

    /// Register a rust function of the form [`EcallHandler`] that will be used as the ECALL.
    fn register_ecall_handler(&mut self, handler: EcallHandler);

    /// Populates a jump table entry for the current instruction being transpiled.
    ///
    /// Effectively should create a mapping from RISCV PC -> absolute address of the instruction.
    ///
    /// This method should be called for "each pc" in the program.
    fn start_instr(&mut self);

    /// This method should be called for "each pc" in the program.
    /// Handle logics when finishing execution of an instruction such as bumping clk and jump to
    /// branch destination.
    fn end_instr(&mut self);

    /// Inspcet a [RiscRegister] using a function pointer.
    ///
    /// Implementors should ensure that [`RiscvTranspiler::start_instr`] is called before this.
    fn inspect_register(&mut self, reg: RiscRegister, handler: DebugFn);

    /// Print an immediate value.
    ///
    /// Implementors should ensure that [`RiscvTranspiler::start_instr`] is called before this.
    fn inspect_immediate(&mut self, imm: u64, handler: DebugFn);

    /// Call an [ExternFn] from the outputted assembly.
    ///
    /// Implementors should ensure that [`RiscvTranspiler::start_instr`] is called before this.
    fn call_extern_fn(&mut self, handler: ExternFn);

    /// Returns the function pointer to the generated code.
    ///
    /// This function is expected to be of the form: `fn(*mut JitContext)`.
    fn finalize(self) -> io::Result<JitFunction>;
}

/// A trait the collects traces, in the form [TraceChunk].
///
/// This type is expected to follow the conventions as described in the [TraceChunk] documentation.
pub trait TraceCollector {
    /// Write the current state of the registers into the trace buf.
    ///
    /// For SP1 this is only called once in the beginning of a "chunk".
    fn trace_registers(&mut self);

    /// Write the value located at rs1 + imm into the trace buf.
    fn trace_mem_value(&mut self, rs1: RiscRegister, imm: u64);

    /// Write the start pc of the trace chunk.
    fn trace_pc_start(&mut self);

    /// Write the start clk of the trace chunk.
    fn trace_clk_start(&mut self);

    /// Write the end clk of the trace chunk.
    fn trace_clk_end(&mut self);
}

pub trait Debuggable {
    fn print_ctx(&mut self);
}

impl<T: RiscvTranspiler> Debuggable for T {
    // Useful only for debugging.
    fn print_ctx(&mut self) {
        extern "C" fn print_ctx(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("pc: {:x}", ctx.pc);
            eprintln!("clk: {}", ctx.clk);
            eprintln!("{:?}", *ctx.registers());
        }

        self.call_extern_fn(print_ctx);
    }
}

#[cfg(not(target_os = "linux"))]
/// Stub implementation for non-linux targets to compile.
pub struct JitFunction {}

/// A type representing a JIT compiled function.
///
/// The underlying function should be of the form [`fn(*mut JitContext)`].
#[cfg(target_os = "linux")]
pub struct JitFunction {
    jump_table: Vec<*const u8>,
    trace_buf_size: usize,
    code: ExecutableBuffer,

    /// The initial memory image.
    initial_memory_image: Arc<HashMap<u64, u64>>,
    pc_start: u64,
    input_buffer: VecDeque<Vec<u8>>,

    /// A stream of public values from the program (global to entire program).
    pub public_values_stream: Vec<u8>,

    /// Keep around the memfd, and pass it to the JIT context,
    /// we can use this to create the COW memory at runtime.
    mem_fd: memfd::Memfd,

    /// During execution, the hints are read by the program, and we store them here.
    /// This is effectively a mapping from start address to the value of the hint.
    pub hints: Vec<(u64, Vec<u8>)>,

    /// The JIT function may stop "in the middle" of an program,
    /// we want to be able to resume it, so this is the information needed to do so.
    pub memory: MmapMut,
    pub pc: u64,
    pub registers: [u64; 32],
    pub clk: u64,
    pub global_clk: u64,
    pub exit_code: u32,

    pub debug_sender: Option<mpsc::SyncSender<Option<debug::State>>>,
}

unsafe impl Send for JitFunction {}

#[cfg(target_os = "linux")]
impl JitFunction {
    pub(crate) fn new(
        code: ExecutableBuffer,
        jump_table: Vec<usize>,
        memory_size: usize,
        trace_buf_size: usize,
        pc_start: u64,
    ) -> std::io::Result<Self> {
        // Adjust the jump table to be absolute addresses.
        let buf_ptr = code.as_ptr();
        let jump_table =
            jump_table.into_iter().map(|offset| unsafe { buf_ptr.add(offset) }).collect();

        let fd = memfd::MemfdOptions::default()
            .create(uuid::Uuid::new_v4().to_string())
            .expect("Failed to create jit memory");

        fd.as_file().set_len((memory_size + std::mem::align_of::<u64>()) as u64)?;

        Ok(Self {
            jump_table,
            code,
            memory: unsafe { MmapOptions::new().no_reserve_swap().map_mut(fd.as_file())? },
            mem_fd: fd,
            trace_buf_size,
            pc: pc_start,
            clk: 1,
            global_clk: 0,
            registers: [0; 32],
            initial_memory_image: Arc::new(HashMap::new()),
            pc_start,
            input_buffer: VecDeque::new(),
            hints: Vec::new(),
            public_values_stream: Vec::new(),
            debug_sender: None,
            exit_code: 0,
        })
    }

    /// Write the initial memory image to the JIT memory.
    ///
    /// # Panics
    ///
    /// Panics if the PC is not the starting PC.
    pub fn with_initial_memory_image(&mut self, memory: Arc<HashMap<u64, u64>>) {
        assert!(
            self.pc == self.pc_start,
            "The initial memory should only be supplied before using the JIT function."
        );

        self.initial_memory_image = memory;
        self.insert_memory_image();
    }

    /// Push an input to the input buffer.
    ///
    /// # Panics
    ///
    /// Panics if the PC is not the starting PC.
    pub fn push_input(&mut self, input: Vec<u8>) {
        assert!(
            self.pc == self.pc_start,
            "The input buffer should only be supplied before using the JIT function."
        );

        self.input_buffer.push_back(input);

        self.hints.reserve(1);
    }

    /// Set the entire input buffer.
    ///
    /// # Panics
    ///
    /// Panics if the PC is not the starting PC.
    pub fn set_input_buffer(&mut self, input: VecDeque<Vec<u8>>) {
        assert!(
            self.pc == self.pc_start,
            "The input buffer should only be supplied before using the JIT function."
        );

        // Reserve the space for the hints.
        self.hints.reserve(input.len());
        self.input_buffer = input;
    }

    /// Call the function, returning the trace buffer, starting at the starting PC of the program.
    ///
    /// If the PC is 0, then the program has completed and we return None.
    ///
    /// # SAFETY
    /// Relies on the builder to emit valid assembly
    /// and that the pointer is valid for the duration of the function call.
    pub unsafe fn call(&mut self) -> Option<TraceChunkRaw> {
        if self.pc == 1 {
            return None;
        }

        let as_fn = std::mem::transmute::<*const u8, fn(*mut JitContext)>(self.code.as_ptr());

        // Ensure the pointer is aligned to the alignment of the MemValue.
        let mut trace_buf =
            MmapMut::map_anon(self.trace_buf_size + std::mem::align_of::<MemValue>())
                .expect("Failed to create trace buf mmap");
        let trace_buf_offset = trace_buf.as_ptr().align_offset(std::mem::align_of::<MemValue>());
        let trace_buf_ptr = trace_buf.as_mut_ptr().add(trace_buf_offset);

        // Ensure the memory pointer is aligned to the alignment of the u64.
        let align_offset = self.memory.as_ptr().align_offset(std::mem::align_of::<u64>());
        let mem_ptr = self.memory.as_mut_ptr().add(align_offset);
        let tracing = self.trace_buf_size > 0;

        // SAFETY:
        // - The jump table is valid for the duration of the function call, its owned by self.
        // - The memory is valid for the duration of the function call, its owned by self.
        // - The trace buf is valid for the duration of the function call, we just allocated it
        // - The input buffer is valid for the duration of the function call, its owned by self.
        let mut ctx = JitContext {
            jump_table: NonNull::new_unchecked(self.jump_table.as_mut_ptr()),
            memory: NonNull::new_unchecked(mem_ptr),
            trace_buf: NonNull::new_unchecked(trace_buf_ptr),
            input_buffer: NonNull::new_unchecked(&mut self.input_buffer),
            hints: NonNull::new_unchecked(&mut self.hints),
            maybe_unconstrained: None,
            public_values_stream: NonNull::new_unchecked(&mut self.public_values_stream),
            memory_fd: self.mem_fd.as_raw_fd(),
            registers: self.registers,
            pc: self.pc,
            clk: self.clk,
            global_clk: self.global_clk,
            is_unconstrained: 0,
            tracing,
            debug_sender: self.debug_sender.clone(),
            exit_code: self.exit_code,
        };

        tracing::debug_span!("JIT function", pc = ctx.pc, clk = ctx.clk).in_scope(|| {
            as_fn(&mut ctx);
        });

        // Update the values we want to preserve.
        self.pc = ctx.pc;
        self.registers = ctx.registers;
        self.clk = ctx.clk;
        self.global_clk = ctx.global_clk;
        self.exit_code = ctx.exit_code;

        tracing.then_some(TraceChunkRaw::new(
            trace_buf.make_read_only().expect("Failed to make trace buf read only"),
        ))
    }

    /// Reset the JIT function to the initial state.
    ///
    /// This will clear the registers, the program counter, the clock, and the memory, restoring the
    /// initial memory image.
    pub fn reset(&mut self) {
        self.pc = self.pc_start;
        self.registers = [0; 32];
        self.clk = 1;
        self.global_clk = 0;
        self.input_buffer = VecDeque::new();
        self.hints = Vec::new();
        self.public_values_stream = Vec::new();

        // Store the original size of the memory.
        let memory_size = self.memory.len();

        // Create a new memfd for the backing memory.
        self.mem_fd = memfd::MemfdOptions::default()
            .create(uuid::Uuid::new_v4().to_string())
            .expect("Failed to create jit memory");

        self.mem_fd
            .as_file()
            .set_len(memory_size as u64)
            .expect("Failed to set memfd size for backing memory.");

        self.memory = unsafe {
            MmapOptions::new()
                .no_reserve_swap()
                .map_mut(self.mem_fd.as_file())
                .expect("Failed to map memory")
        };

        self.insert_memory_image();
    }

    fn insert_memory_image(&mut self) {
        for (addr, val) in self.initial_memory_image.iter() {
            // Technically, this crate is probably only used on little endian targets, but just to
            // sure.
            let bytes = val.to_le_bytes();

            #[cfg(debug_assertions)]
            if addr % 8 > 0 {
                panic!("Address {addr} is not aligned to 8");
            }

            let actual_addr = 2 * addr + 8;
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    self.memory.as_mut_ptr().add(actual_addr as usize),
                    bytes.len(),
                )
            };
        }
    }
}

pub struct MemoryView<'a> {
    pub memory: &'a MmapMut,
}

impl<'a> MemoryView<'a> {
    pub const fn new(memory: &'a MmapMut) -> Self {
        Self { memory }
    }

    /// Read a word from the memory at the address.
    ///
    /// # Panics
    ///
    /// Panics if the address is not aligned to 8 bytes.
    pub fn get(&self, addr: u64) -> MemValue {
        assert!(addr.is_multiple_of(8), "Address {addr} is not aligned to 8");

        let word_address = addr / 8;
        let entry_ptr = self.memory.as_ptr() as *mut MemValue;

        unsafe { std::ptr::read(entry_ptr.add(word_address as usize)) }
    }
}
