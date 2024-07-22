mod context;
mod hooks;
mod instruction;
mod io;
mod memory;
mod opcode;
mod program;
mod record;
mod register;
mod report;
mod state;
mod syscall;
#[macro_use]
mod utils;
mod subproof;

pub use context::*;
pub use hooks::*;
pub use instruction::*;
pub use memory::*;
pub use opcode::*;
pub use program::*;
pub use record::*;
pub use register::*;
pub use report::*;
pub use state::*;
pub use subproof::*;
pub use syscall::*;
pub use utils::*;

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;
use std::io::Write;
use std::sync::Arc;

use thiserror::Error;

use crate::alu::create_alu_lookup_id;
use crate::alu::create_alu_lookups;
use crate::bytes::NUM_BYTE_LOOKUP_CHANNELS;
use crate::memory::MemoryInitializeFinalizeEvent;
use crate::utils::SP1CoreOpts;
use crate::{alu::AluEvent, cpu::CpuEvent};

/// An implementation of a runtime for the SP1 RISC-V zkVM.
///
/// The runtime is responsible for executing a user program and tracing important events which occur
/// during execution (i.e., memory reads, alu operations, etc).
///
/// For more information on the RV32IM instruction set, see the following:
/// https://www.cs.sfu.ca/~ashriram/Courses/CS295/assets/notebooks/RISCV/RISCV_CARD.pdf
pub struct Runtime<'a> {
    /// The program.
    pub program: Arc<Program>,

    /// The state of the execution.
    pub state: ExecutionState,

    /// The current trace of the execution that is being collected.
    pub record: ExecutionRecord,

    /// The collected records, split by cpu cycles.
    pub records: Vec<ExecutionRecord>,

    /// The memory accesses for the current cycle.
    pub memory_accesses: MemoryAccessRecord,

    /// The maximum size of each shard.
    pub shard_size: u32,

    pub shard_batch_size: u32,

    /// A counter for the number of cycles that have been executed in certain functions.
    pub cycle_tracker: HashMap<String, (u64, u32)>,

    /// A buffer for stdout and stderr IO.
    pub io_buf: HashMap<u32, String>,

    /// A buffer for writing trace events to a file.
    pub trace_buf: Option<BufWriter<File>>,

    /// Whether the runtime is in constrained mode or not.
    ///
    /// In unconstrained mode, any events, clock, register, or memory changes are reset after leaving
    /// the unconstrained block. The only thing preserved is writes to the input stream.
    pub unconstrained: bool,

    /// The state of the runtime when in unconstrained mode.
    pub(crate) unconstrained_state: ForkState,

    /// The mapping between syscall codes and their implementations.
    pub syscall_map: HashMap<SyscallCode, Arc<dyn Syscall>>,

    /// The maximum number of cycles for a syscall.
    pub max_syscall_cycles: u32,

    /// Whether to emit events during execution.
    pub emit_events: bool,

    /// Report of the program execution.
    pub report: ExecutionReport,

    /// Whether we should write to the report.
    pub print_report: bool,

    /// Verifier used to sanity check `verify_sp1_proof` during runtime.
    pub subproof_verifier: Arc<dyn SubproofVerifier + 'a>,

    /// Registry of hooks, to be invoked by writing to certain file descriptors.
    pub hook_registry: HookRegistry<'a>,

    // The options for the runtime.
    pub opts: SP1CoreOpts,

    /// The maximum number of cpu cycles to use for execution.
    pub max_cycles: Option<u64>,
}

#[derive(Error, Debug)]
pub enum ExecutionError {
    #[error("execution failed with exit code {0}")]
    HaltWithNonZeroExitCode(u32),
    #[error("invalid memory access for opcode {0} and address {1}")]
    InvalidMemoryAccess(Opcode, u32),
    #[error("unimplemented syscall {0}")]
    UnsupportedSyscall(u32),
    #[error("breakpoint encountered")]
    Breakpoint(),
    #[error("exceeded cycle limit of {0}")]
    ExceededCycleLimit(u64),
    #[error("got unimplemented as opcode")]
    Unimplemented(),
}

impl<'a> Runtime<'a> {
    // Create a new runtime from a program and options.
    pub fn new(program: Program, opts: SP1CoreOpts) -> Self {
        Self::with_context(program, opts, Default::default())
    }

    /// Create a new runtime from a program, options, and a context.
    pub fn with_context(program: Program, opts: SP1CoreOpts, context: SP1Context<'a>) -> Self {
        // Create a shared reference to the program.
        let program = Arc::new(program);

        // Create a default record with the program.
        let record = ExecutionRecord {
            program: program.clone(),
            ..Default::default()
        };

        // If TRACE_FILE is set, initialize the trace buffer.
        let trace_buf = if let Ok(trace_file) = std::env::var("TRACE_FILE") {
            let file = File::create(trace_file).unwrap();
            Some(BufWriter::new(file))
        } else {
            None
        };

        // Determine the maximum number of cycles for any syscall.
        let syscall_map = default_syscall_map();
        let max_syscall_cycles = syscall_map
            .values()
            .map(|syscall| syscall.num_extra_cycles())
            .max()
            .unwrap_or(0);

        let subproof_verifier = context
            .subproof_verifier
            .unwrap_or_else(|| Arc::new(DefaultSubproofVerifier::new()));
        let hook_registry = context.hook_registry.unwrap_or_default();

        Self {
            record,
            records: vec![],
            state: ExecutionState::new(program.pc_start),
            program,
            memory_accesses: MemoryAccessRecord::default(),
            shard_size: (opts.shard_size as u32) * 4,
            shard_batch_size: opts.shard_batch_size as u32,
            cycle_tracker: HashMap::new(),
            io_buf: HashMap::new(),
            trace_buf,
            unconstrained: false,
            unconstrained_state: ForkState::default(),
            syscall_map,
            emit_events: true,
            max_syscall_cycles,
            report: ExecutionReport::default(),
            print_report: false,
            subproof_verifier,
            hook_registry,
            opts,
            max_cycles: context.max_cycles,
        }
    }

    /// Invokes the hook corresponding to the given file descriptor `fd` with the data `buf`,
    /// returning the resulting data.
    pub fn hook(&self, fd: u32, buf: &[u8]) -> Vec<Vec<u8>> {
        self.hook_registry
            .get(&fd)
            .unwrap()
            .invoke_hook(self.hook_env(), buf)
    }

    /// Prepare a `HookEnv` for use by hooks.
    pub fn hook_env<'b>(&'b self) -> HookEnv<'b, 'a> {
        HookEnv { runtime: self }
    }

    /// Recover runtime state from a program and existing execution state.
    pub fn recover(program: Program, state: ExecutionState, opts: SP1CoreOpts) -> Self {
        let mut runtime = Self::new(program.clone(), opts);
        runtime.state = state;
        runtime
    }

    /// Get the current values of the registers.
    pub fn registers(&self) -> [u32; 32] {
        let mut registers = [0; 32];
        for i in 0..32 {
            let addr = Register::from_u32(i as u32) as u32;
            registers[i] = match self.state.memory.get(&addr) {
                Some(record) => record.value,
                None => 0,
            };
        }
        registers
    }

    /// Get the current value of a register.
    pub fn register(&self, register: Register) -> u32 {
        let addr = register as u32;
        match self.state.memory.get(&addr) {
            Some(record) => record.value,
            None => 0,
        }
    }

    /// Get the current value of a word.
    pub fn word(&self, addr: u32) -> u32 {
        match self.state.memory.get(&addr) {
            Some(record) => record.value,
            None => 0,
        }
    }

    /// Get the current value of a byte.
    pub fn byte(&self, addr: u32) -> u8 {
        let word = self.word(addr - addr % 4);
        (word >> ((addr % 4) * 8)) as u8
    }

    /// Get the current timestamp for a given memory access position.
    pub const fn timestamp(&self, position: &MemoryAccessPosition) -> u32 {
        self.state.clk + *position as u32
    }

    /// Get the current shard.
    #[inline]
    pub fn shard(&self) -> u32 {
        self.state.current_shard
    }

    #[inline]
    pub fn channel(&self) -> u8 {
        self.state.channel
    }

    /// Read a word from memory and create an access record.
    pub fn mr(&mut self, addr: u32, shard: u32, timestamp: u32) -> MemoryReadRecord {
        // Get the memory record entry.
        let entry = self.state.memory.entry(addr);

        // If we're in unconstrained mode, we don't want to modify state, so we'll save the
        // original state if it's the first time modifying it.
        if self.unconstrained {
            let record = match entry {
                Entry::Occupied(ref entry) => Some(entry.get()),
                Entry::Vacant(_) => None,
            };
            self.unconstrained_state
                .memory_diff
                .entry(addr)
                .or_insert(record.copied());
        }

        // If it's the first time accessing this address, initialize previous values.
        let record: &mut MemoryRecord = match entry {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                // If addr has a specific value to be initialized with, use that, otherwise 0.
                let value = self.state.uninitialized_memory.get(&addr).unwrap_or(&0);
                entry.insert(MemoryRecord {
                    value: *value,
                    shard: 0,
                    timestamp: 0,
                })
            }
        };
        let value = record.value;
        let prev_shard = record.shard;
        let prev_timestamp = record.timestamp;
        record.shard = shard;
        record.timestamp = timestamp;

        // Construct the memory read record.
        MemoryReadRecord::new(value, shard, timestamp, prev_shard, prev_timestamp)
    }

    /// Write a word to memory and create an access record.
    pub fn mw(&mut self, addr: u32, value: u32, shard: u32, timestamp: u32) -> MemoryWriteRecord {
        // Get the memory record entry.
        let entry = self.state.memory.entry(addr);

        // If we're in unconstrained mode, we don't want to modify state, so we'll save the
        // original state if it's the first time modifying it.
        if self.unconstrained {
            let record = match entry {
                Entry::Occupied(ref entry) => Some(entry.get()),
                Entry::Vacant(_) => None,
            };
            self.unconstrained_state
                .memory_diff
                .entry(addr)
                .or_insert(record.copied());
        }

        // If it's the first time accessing this address, initialize previous values.
        let record: &mut MemoryRecord = match entry {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                // If addr has a specific value to be initialized with, use that, otherwise 0.
                let value = self.state.uninitialized_memory.get(&addr).unwrap_or(&0);

                entry.insert(MemoryRecord {
                    value: *value,
                    shard: 0,
                    timestamp: 0,
                })
            }
        };
        let prev_value = record.value;
        let prev_shard = record.shard;
        let prev_timestamp = record.timestamp;
        record.value = value;
        record.shard = shard;
        record.timestamp = timestamp;

        // Construct the memory write record.
        MemoryWriteRecord::new(
            value,
            shard,
            timestamp,
            prev_value,
            prev_shard,
            prev_timestamp,
        )
    }

    /// Read from memory, assuming that all addresses are aligned.
    pub fn mr_cpu(&mut self, addr: u32, position: MemoryAccessPosition) -> u32 {
        // Assert that the address is aligned.
        assert_valid_memory_access!(addr, position);

        // Read the address from memory and create a memory read record.
        let record = self.mr(addr, self.shard(), self.timestamp(&position));

        // If we're not in unconstrained mode, record the access for the current cycle.
        if !self.unconstrained && self.emit_events {
            match position {
                MemoryAccessPosition::A => self.memory_accesses.a = Some(record.into()),
                MemoryAccessPosition::B => self.memory_accesses.b = Some(record.into()),
                MemoryAccessPosition::C => self.memory_accesses.c = Some(record.into()),
                MemoryAccessPosition::Memory => self.memory_accesses.memory = Some(record.into()),
            }
        }
        record.value
    }

    /// Write to memory.
    pub fn mw_cpu(&mut self, addr: u32, value: u32, position: MemoryAccessPosition) {
        // Assert that the address is aligned.
        assert_valid_memory_access!(addr, position);

        // Read the address from memory and create a memory read record.
        let record = self.mw(addr, value, self.shard(), self.timestamp(&position));

        // If we're not in unconstrained mode, record the access for the current cycle.
        if !self.unconstrained {
            match position {
                MemoryAccessPosition::A => {
                    assert!(self.memory_accesses.a.is_none());
                    self.memory_accesses.a = Some(record.into());
                }
                MemoryAccessPosition::B => {
                    assert!(self.memory_accesses.b.is_none());
                    self.memory_accesses.b = Some(record.into());
                }
                MemoryAccessPosition::C => {
                    assert!(self.memory_accesses.c.is_none());
                    self.memory_accesses.c = Some(record.into());
                }
                MemoryAccessPosition::Memory => {
                    assert!(self.memory_accesses.memory.is_none());
                    self.memory_accesses.memory = Some(record.into());
                }
            }
        }
    }

    /// Read from a register.
    pub fn rr(&mut self, register: Register, position: MemoryAccessPosition) -> u32 {
        self.mr_cpu(register as u32, position)
    }

    /// Write to a register.
    pub fn rw(&mut self, register: Register, value: u32) {
        // The only time we are writing to a register is when it is in operand A.
        // Register %x0 should always be 0. See 2.6 Load and Store Instruction on
        // P.18 of the RISC-V spec. We always write 0 to %x0.
        if register == Register::X0 {
            self.mw_cpu(register as u32, 0, MemoryAccessPosition::A);
        } else {
            self.mw_cpu(register as u32, value, MemoryAccessPosition::A)
        }
    }

    /// Emit a CPU event.
    #[allow(clippy::too_many_arguments)]
    fn emit_cpu(
        &mut self,
        shard: u32,
        channel: u8,
        clk: u32,
        pc: u32,
        next_pc: u32,
        instruction: Instruction,
        a: u32,
        b: u32,
        c: u32,
        memory_store_value: Option<u32>,
        record: MemoryAccessRecord,
        exit_code: u32,
        lookup_id: u128,
        syscall_lookup_id: u128,
    ) {
        let cpu_event = CpuEvent {
            shard,
            channel,
            clk,
            pc,
            next_pc,
            instruction,
            a,
            a_record: record.a,
            b,
            b_record: record.b,
            c,
            c_record: record.c,
            memory: memory_store_value,
            memory_record: record.memory,
            exit_code,
            alu_lookup_id: lookup_id,
            syscall_lookup_id,
            memory_add_lookup_id: create_alu_lookup_id(),
            memory_sub_lookup_id: create_alu_lookup_id(),
            branch_lt_lookup_id: create_alu_lookup_id(),
            branch_gt_lookup_id: create_alu_lookup_id(),
            branch_add_lookup_id: create_alu_lookup_id(),
            jump_jal_lookup_id: create_alu_lookup_id(),
            jump_jalr_lookup_id: create_alu_lookup_id(),
            auipc_lookup_id: create_alu_lookup_id(),
        };

        self.record.cpu_events.push(cpu_event);
    }

    /// Emit an ALU event.
    fn emit_alu(&mut self, clk: u32, opcode: Opcode, a: u32, b: u32, c: u32, lookup_id: u128) {
        let event = AluEvent {
            lookup_id,
            shard: self.shard(),
            clk,
            channel: self.channel(),
            opcode,
            a,
            b,
            c,
            sub_lookups: create_alu_lookups(),
        };
        match opcode {
            Opcode::ADD => {
                self.record.add_events.push(event);
            }
            Opcode::SUB => {
                self.record.sub_events.push(event);
            }
            Opcode::XOR | Opcode::OR | Opcode::AND => {
                self.record.bitwise_events.push(event);
            }
            Opcode::SLL => {
                self.record.shift_left_events.push(event);
            }
            Opcode::SRL | Opcode::SRA => {
                self.record.shift_right_events.push(event);
            }
            Opcode::SLT | Opcode::SLTU => {
                self.record.lt_events.push(event);
            }
            Opcode::MUL | Opcode::MULHU | Opcode::MULHSU | Opcode::MULH => {
                self.record.mul_events.push(event);
            }
            Opcode::DIVU | Opcode::REMU | Opcode::DIV | Opcode::REM => {
                self.record.divrem_events.push(event);
            }
            _ => {}
        }
    }

    /// Fetch the destination register and input operand values for an ALU instruction.
    fn alu_rr(&mut self, instruction: Instruction) -> (Register, u32, u32) {
        if !instruction.imm_c {
            let (rd, rs1, rs2) = instruction.r_type();
            let c = self.rr(rs2, MemoryAccessPosition::C);
            let b = self.rr(rs1, MemoryAccessPosition::B);
            (rd, b, c)
        } else if !instruction.imm_b && instruction.imm_c {
            let (rd, rs1, imm) = instruction.i_type();
            let (rd, b, c) = (rd, self.rr(rs1, MemoryAccessPosition::B), imm);
            (rd, b, c)
        } else {
            assert!(instruction.imm_b && instruction.imm_c);
            let (rd, b, c) = (
                Register::from_u32(instruction.op_a),
                instruction.op_b,
                instruction.op_c,
            );
            (rd, b, c)
        }
    }

    /// Set the destination register with the result and emit an ALU event.
    fn alu_rw(
        &mut self,
        instruction: Instruction,
        rd: Register,
        a: u32,
        b: u32,
        c: u32,
        lookup_id: u128,
    ) {
        self.rw(rd, a);
        if self.emit_events {
            self.emit_alu(self.state.clk, instruction.opcode, a, b, c, lookup_id);
        }
    }

    /// Fetch the input operand values for a load instruction.
    fn load_rr(&mut self, instruction: Instruction) -> (Register, u32, u32, u32, u32) {
        let (rd, rs1, imm) = instruction.i_type();
        let (b, c) = (self.rr(rs1, MemoryAccessPosition::B), imm);
        let addr = b.wrapping_add(c);
        let memory_value = self.mr_cpu(align(addr), MemoryAccessPosition::Memory);
        (rd, b, c, addr, memory_value)
    }

    /// Fetch the input operand values for a store instruction.
    fn store_rr(&mut self, instruction: Instruction) -> (u32, u32, u32, u32, u32) {
        let (rs1, rs2, imm) = instruction.s_type();
        let c = imm;
        let b = self.rr(rs2, MemoryAccessPosition::B);
        let a = self.rr(rs1, MemoryAccessPosition::A);
        let addr = b.wrapping_add(c);
        let memory_value = self.word(align(addr));
        (a, b, c, addr, memory_value)
    }

    /// Fetch the input operand values for a branch instruction.
    fn branch_rr(&mut self, instruction: Instruction) -> (u32, u32, u32) {
        let (rs1, rs2, imm) = instruction.b_type();
        let c = imm;
        let b = self.rr(rs2, MemoryAccessPosition::B);
        let a = self.rr(rs1, MemoryAccessPosition::A);
        (a, b, c)
    }

    /// Fetch the instruction at the current program counter.
    fn fetch(&self) -> Instruction {
        let idx = ((self.state.pc - self.program.pc_base) / 4) as usize;
        self.program.instructions[idx]
    }

    /// Execute the given instruction over the current state of the runtime.
    fn execute_instruction(&mut self, instruction: Instruction) -> Result<(), ExecutionError> {
        let mut pc = self.state.pc;
        let mut clk = self.state.clk;
        let mut exit_code = 0u32;

        let mut next_pc = self.state.pc.wrapping_add(4);

        let rd: Register;
        let (a, b, c): (u32, u32, u32);
        let (addr, memory_read_value): (u32, u32);
        let mut memory_store_value: Option<u32> = None;
        self.memory_accesses = MemoryAccessRecord::default();

        let lookup_id = create_alu_lookup_id();
        let syscall_lookup_id = create_alu_lookup_id();

        if self.print_report && !self.unconstrained {
            self.report
                .opcode_counts
                .entry(instruction.opcode)
                .and_modify(|c| *c += 1)
                .or_insert(1);
        }

        match instruction.opcode {
            // Arithmetic instructions.
            Opcode::ADD => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_add(c);
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::SUB => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_sub(c);
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::XOR => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b ^ c;
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::OR => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b | c;
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::AND => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b & c;
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::SLL => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_shl(c);
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::SRL => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_shr(c);
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::SRA => {
                (rd, b, c) = self.alu_rr(instruction);
                a = (b as i32).wrapping_shr(c) as u32;
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::SLT => {
                (rd, b, c) = self.alu_rr(instruction);
                a = if (b as i32) < (c as i32) { 1 } else { 0 };
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::SLTU => {
                (rd, b, c) = self.alu_rr(instruction);
                a = if b < c { 1 } else { 0 };
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }

            // Load instructions.
            Opcode::LB => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                let value = (memory_read_value).to_le_bytes()[(addr % 4) as usize];
                a = ((value as i8) as i32) as u32;
                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }
            Opcode::LH => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                if addr % 2 != 0 {
                    return Err(ExecutionError::InvalidMemoryAccess(Opcode::LH, addr));
                }
                let value = match (addr >> 1) % 2 {
                    0 => memory_read_value & 0x0000FFFF,
                    1 => (memory_read_value & 0xFFFF0000) >> 16,
                    _ => unreachable!(),
                };
                a = ((value as i16) as i32) as u32;
                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }
            Opcode::LW => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                if addr % 4 != 0 {
                    return Err(ExecutionError::InvalidMemoryAccess(Opcode::LW, addr));
                }
                a = memory_read_value;
                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }
            Opcode::LBU => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                let value = (memory_read_value).to_le_bytes()[(addr % 4) as usize];
                a = value as u32;
                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }
            Opcode::LHU => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                if addr % 2 != 0 {
                    return Err(ExecutionError::InvalidMemoryAccess(Opcode::LHU, addr));
                }
                let value = match (addr >> 1) % 2 {
                    0 => memory_read_value & 0x0000FFFF,
                    1 => (memory_read_value & 0xFFFF0000) >> 16,
                    _ => unreachable!(),
                };
                a = (value as u16) as u32;
                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }

            // Store instructions.
            Opcode::SB => {
                (a, b, c, addr, memory_read_value) = self.store_rr(instruction);
                let value = match addr % 4 {
                    0 => (a & 0x000000FF) + (memory_read_value & 0xFFFFFF00),
                    1 => ((a & 0x000000FF) << 8) + (memory_read_value & 0xFFFF00FF),
                    2 => ((a & 0x000000FF) << 16) + (memory_read_value & 0xFF00FFFF),
                    3 => ((a & 0x000000FF) << 24) + (memory_read_value & 0x00FFFFFF),
                    _ => unreachable!(),
                };
                memory_store_value = Some(value);
                self.mw_cpu(align(addr), value, MemoryAccessPosition::Memory);
            }
            Opcode::SH => {
                (a, b, c, addr, memory_read_value) = self.store_rr(instruction);
                if addr % 2 != 0 {
                    return Err(ExecutionError::InvalidMemoryAccess(Opcode::SH, addr));
                }
                let value = match (addr >> 1) % 2 {
                    0 => (a & 0x0000FFFF) + (memory_read_value & 0xFFFF0000),
                    1 => ((a & 0x0000FFFF) << 16) + (memory_read_value & 0x0000FFFF),
                    _ => unreachable!(),
                };
                memory_store_value = Some(value);
                self.mw_cpu(align(addr), value, MemoryAccessPosition::Memory);
            }
            Opcode::SW => {
                (a, b, c, addr, _) = self.store_rr(instruction);
                if addr % 4 != 0 {
                    return Err(ExecutionError::InvalidMemoryAccess(Opcode::SW, addr));
                }
                let value = a;
                memory_store_value = Some(value);
                self.mw_cpu(align(addr), value, MemoryAccessPosition::Memory);
            }

            // B-type instructions.
            Opcode::BEQ => {
                (a, b, c) = self.branch_rr(instruction);
                if a == b {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }
            Opcode::BNE => {
                (a, b, c) = self.branch_rr(instruction);
                if a != b {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }
            Opcode::BLT => {
                (a, b, c) = self.branch_rr(instruction);
                if (a as i32) < (b as i32) {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }
            Opcode::BGE => {
                (a, b, c) = self.branch_rr(instruction);
                if (a as i32) >= (b as i32) {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }
            Opcode::BLTU => {
                (a, b, c) = self.branch_rr(instruction);
                if a < b {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }
            Opcode::BGEU => {
                (a, b, c) = self.branch_rr(instruction);
                if a >= b {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }

            // Jump instructions.
            Opcode::JAL => {
                let (rd, imm) = instruction.j_type();
                (b, c) = (imm, 0);
                a = self.state.pc + 4;
                self.rw(rd, a);
                next_pc = self.state.pc.wrapping_add(imm);
            }
            Opcode::JALR => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1, MemoryAccessPosition::B), imm);
                a = self.state.pc + 4;
                self.rw(rd, a);
                next_pc = b.wrapping_add(c);
            }

            // Upper immediate instructions.
            Opcode::AUIPC => {
                let (rd, imm) = instruction.u_type();
                (b, c) = (imm, imm);
                a = self.state.pc.wrapping_add(b);
                self.rw(rd, a);
            }

            // System instructions.
            Opcode::ECALL => {
                // We peek at register x5 to get the syscall id. The reason we don't `self.rr` this
                // register is that we write to it later.
                let t0 = Register::X5;
                let syscall_id = self.register(t0);
                c = self.rr(Register::X11, MemoryAccessPosition::C);
                b = self.rr(Register::X10, MemoryAccessPosition::B);
                let syscall = SyscallCode::from_u32(syscall_id);

                if self.print_report && !self.unconstrained {
                    self.report
                        .syscall_counts
                        .entry(syscall)
                        .and_modify(|c| *c += 1)
                        .or_insert(1);
                }

                let syscall_impl = self.get_syscall(syscall).cloned();
                let mut precompile_rt = SyscallContext::new(self);
                precompile_rt.syscall_lookup_id = syscall_lookup_id;
                let (precompile_next_pc, precompile_cycles, returned_exit_code) =
                    if let Some(syscall_impl) = syscall_impl {
                        // Executing a syscall optionally returns a value to write to the t0 register.
                        // If it returns None, we just keep the syscall_id in t0.
                        let res = syscall_impl.execute(&mut precompile_rt, b, c);
                        if let Some(val) = res {
                            a = val;
                        } else {
                            a = syscall_id;
                        }

                        // If the syscall is `HALT` and the exit code is non-zero, return an error.
                        if syscall == SyscallCode::HALT && precompile_rt.exit_code != 0 {
                            return Err(ExecutionError::HaltWithNonZeroExitCode(
                                precompile_rt.exit_code,
                            ));
                        }

                        (
                            precompile_rt.next_pc,
                            syscall_impl.num_extra_cycles(),
                            precompile_rt.exit_code,
                        )
                    } else {
                        return Err(ExecutionError::UnsupportedSyscall(syscall_id));
                    };

                // Allow the syscall impl to modify state.clk/pc (exit unconstrained does this)
                clk = self.state.clk;
                pc = self.state.pc;

                self.rw(t0, a);
                next_pc = precompile_next_pc;
                self.state.clk += precompile_cycles;
                exit_code = returned_exit_code;

                // Update the syscall counts.
                let syscall_count = self.state.syscall_counts.entry(syscall).or_insert(0);
                let (threshold, multiplier) = match syscall {
                    SyscallCode::KECCAK_PERMUTE => {
                        (self.opts.split_opts.keccak_split_threshold, 24)
                    }
                    SyscallCode::SHA_EXTEND => {
                        (self.opts.split_opts.sha_extend_split_threshold, 48)
                    }
                    SyscallCode::SHA_COMPRESS => {
                        (self.opts.split_opts.sha_compress_split_threshold, 80)
                    }
                    _ => (self.opts.split_opts.deferred_shift_threshold, 1),
                };
                let nonce = (((*syscall_count as usize) % threshold) * multiplier) as u32;
                self.record.nonce_lookup.insert(syscall_lookup_id, nonce);
                *syscall_count += 1;
            }
            Opcode::EBREAK => {
                return Err(ExecutionError::Breakpoint());
            }

            // Multiply instructions.
            Opcode::MUL => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_mul(c);
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::MULH => {
                (rd, b, c) = self.alu_rr(instruction);
                a = (((b as i32) as i64).wrapping_mul((c as i32) as i64) >> 32) as u32;
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::MULHU => {
                (rd, b, c) = self.alu_rr(instruction);
                a = ((b as u64).wrapping_mul(c as u64) >> 32) as u32;
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::MULHSU => {
                (rd, b, c) = self.alu_rr(instruction);
                a = (((b as i32) as i64).wrapping_mul(c as i64) >> 32) as u32;
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::DIV => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = u32::MAX;
                } else {
                    a = (b as i32).wrapping_div(c as i32) as u32;
                }
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::DIVU => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = u32::MAX;
                } else {
                    a = b.wrapping_div(c);
                }
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::REM => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = b;
                } else {
                    a = (b as i32).wrapping_rem(c as i32) as u32;
                }
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }
            Opcode::REMU => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = b;
                } else {
                    a = b.wrapping_rem(c);
                }
                self.alu_rw(instruction, rd, a, b, c, lookup_id);
            }

            // See https://github.com/riscv-non-isa/riscv-asm-manual/blob/master/riscv-asm.md#instruction-aliases
            Opcode::UNIMP => {
                return Err(ExecutionError::Unimplemented());
            }
        }

        // Update the program counter.
        self.state.pc = next_pc;

        // Update the clk to the next cycle.
        self.state.clk += 4;

        let channel = self.channel();

        // Update the channel to the next cycle.
        if !self.unconstrained {
            self.state.channel = (self.state.channel + 1) % NUM_BYTE_LOOKUP_CHANNELS;
        }

        // Emit the CPU event for this cycle.
        if self.emit_events {
            self.emit_cpu(
                self.shard(),
                channel,
                clk,
                pc,
                next_pc,
                instruction,
                a,
                b,
                c,
                memory_store_value,
                self.memory_accesses,
                exit_code,
                lookup_id,
                syscall_lookup_id,
            );
        };
        Ok(())
    }

    /// Executes one cycle of the program, returning whether the program has finished.
    #[inline]
    fn execute_cycle(&mut self) -> Result<bool, ExecutionError> {
        // Fetch the instruction at the current program counter.
        let instruction = self.fetch();

        // Log the current state of the runtime.
        self.log(&instruction);

        // Execute the instruction.
        self.execute_instruction(instruction)?;

        // Increment the clock.
        self.state.global_clk += 1;

        // If there's not enough cycles left for another instruction, move to the next shard.
        // We multiply by 4 because clk is incremented by 4 for each normal instruction.
        if !self.unconstrained && self.max_syscall_cycles + self.state.clk >= self.shard_size {
            self.state.current_shard += 1;
            self.state.clk = 0;
            self.state.channel = 0;

            self.bump_record();
        }

        // If the cycle limit is exceeded, return an error.
        if let Some(max_cycles) = self.max_cycles {
            if self.state.global_clk >= max_cycles {
                return Err(ExecutionError::ExceededCycleLimit(max_cycles));
            }
        }

        Ok(self.state.pc.wrapping_sub(self.program.pc_base)
            >= (self.program.instructions.len() * 4) as u32)
    }

    pub fn bump_record(&mut self) {
        let removed_record =
            std::mem::replace(&mut self.record, ExecutionRecord::new(self.program.clone()));
        let public_values = removed_record.public_values;
        self.record.public_values = public_values;
        self.records.push(removed_record);
    }

    /// Execute up to `self.shard_batch_size` cycles, returning the events emitted and whether the program ended.
    pub fn execute_record(&mut self) -> Result<(Vec<ExecutionRecord>, bool), ExecutionError> {
        self.emit_events = true;
        self.print_report = true;
        let done = self.execute()?;
        Ok((std::mem::take(&mut self.records), done))
    }

    /// Execute up to `self.shard_batch_size` cycles, returning a copy of the prestate and whether the program ended.
    pub fn execute_state(&mut self) -> Result<(ExecutionState, bool), ExecutionError> {
        self.emit_events = false;
        self.print_report = false;
        let state = self.state.clone();
        let done = self.execute()?;
        Ok((state, done))
    }

    fn initialize(&mut self) {
        self.state.clk = 0;
        self.state.channel = 0;

        tracing::debug!("loading memory image");
        for (addr, value) in self.program.memory_image.iter() {
            self.state.memory.insert(
                *addr,
                MemoryRecord {
                    value: *value,
                    shard: 0,
                    timestamp: 0,
                },
            );
        }
    }

    pub fn run_untraced(&mut self) -> Result<(), ExecutionError> {
        self.emit_events = false;
        self.print_report = true;
        while !self.execute()? {}
        Ok(())
    }

    pub fn run(&mut self) -> Result<(), ExecutionError> {
        self.emit_events = true;
        self.print_report = true;
        while !self.execute()? {}
        Ok(())
    }

    pub fn dry_run(&mut self) {
        self.emit_events = false;
        while !self.execute().unwrap() {}
    }

    /// Executes up to `self.shard_batch_size` cycles of the program, returning whether the program has finished.
    fn execute(&mut self) -> Result<bool, ExecutionError> {
        // Get the program.
        let program = self.program.clone();

        // Get the current shard.
        let start_shard = self.state.current_shard;

        // If it's the first cycle, initialize the program.
        if self.state.global_clk == 0 {
            self.initialize();
        }

        // Loop until we've executed `self.shard_batch_size` shards if `self.shard_batch_size` is set.
        let mut done = false;
        let mut current_shard = self.state.current_shard;
        let mut num_shards_executed = 0;
        loop {
            if self.execute_cycle()? {
                done = true;
                break;
            }

            if self.shard_batch_size > 0 && current_shard != self.state.current_shard {
                num_shards_executed += 1;
                current_shard = self.state.current_shard;
                if num_shards_executed == self.shard_batch_size {
                    break;
                }
            }
        }

        // Get the final public values.
        let public_values = self.record.public_values;

        // Push the remaining execution record, if there are any CPU events.
        if !self.record.cpu_events.is_empty() {
            self.bump_record();
        }

        if done {
            self.postprocess();

            // Push the remaining execution record with memory initialize & finalize events.
            self.bump_record();
        }

        // Set the global public values for all shards.
        let mut last_next_pc = 0;
        let mut last_exit_code = 0;
        for (i, record) in self.records.iter_mut().enumerate() {
            record.program = program.clone();
            record.public_values = public_values;
            record.public_values.committed_value_digest = public_values.committed_value_digest;
            record.public_values.deferred_proofs_digest = public_values.deferred_proofs_digest;
            record.public_values.execution_shard = start_shard + i as u32;
            if !record.cpu_events.is_empty() {
                record.public_values.start_pc = record.cpu_events[0].pc;
                record.public_values.next_pc = record.cpu_events.last().unwrap().next_pc;
                record.public_values.exit_code = record.cpu_events.last().unwrap().exit_code;
                last_next_pc = record.public_values.next_pc;
                last_exit_code = record.public_values.exit_code;
            } else {
                record.public_values.start_pc = last_next_pc;
                record.public_values.next_pc = last_next_pc;
                record.public_values.exit_code = last_exit_code;
            }
        }

        Ok(done)
    }

    fn postprocess(&mut self) {
        // Flush remaining stdout/stderr
        for (fd, buf) in self.io_buf.iter() {
            if !buf.is_empty() {
                match fd {
                    1 => {
                        println!("stdout: {}", buf);
                    }
                    2 => {
                        println!("stderr: {}", buf);
                    }
                    _ => {}
                }
            }
        }

        // Flush trace buf
        if let Some(ref mut buf) = self.trace_buf {
            buf.flush().unwrap();
        }

        // Ensure that all proofs and input bytes were read, otherwise warn the user.
        if self.state.proof_stream_ptr != self.state.proof_stream.len() {
            panic!(
                "Not all proofs were read. Proving will fail during recursion. Did you pass too many proofs in or forget to call verify_sp1_proof?"
            );
        }
        if self.state.input_stream_ptr != self.state.input_stream.len() {
            log::warn!("Not all input bytes were read.");
        }

        // SECTION: Set up all MemoryInitializeFinalizeEvents needed for memory argument.
        let memory_finalize_events = &mut self.record.memory_finalize_events;

        // We handle the addr = 0 case separately, as we constrain it to be 0 in the first row
        // of the memory finalize table so it must be first in the array of events.
        let addr_0_record = self.state.memory.get(&0u32);

        let addr_0_final_record = match addr_0_record {
            Some(record) => record,
            None => &MemoryRecord {
                value: 0,
                shard: 0,
                timestamp: 1,
            },
        };
        memory_finalize_events.push(MemoryInitializeFinalizeEvent::finalize_from_record(
            0,
            addr_0_final_record,
        ));

        let memory_initialize_events = &mut self.record.memory_initialize_events;
        let addr_0_initialize_event =
            MemoryInitializeFinalizeEvent::initialize(0, 0, addr_0_record.is_some());
        memory_initialize_events.push(addr_0_initialize_event);

        for addr in self.state.memory.keys() {
            if addr == &0 {
                // Handled above.
                continue;
            }

            // Program memory is initialized in the MemoryProgram chip and doesn't require any events,
            // so we only send init events for other memory addresses.
            if !self.record.program.memory_image.contains_key(addr) {
                let initial_value = self.state.uninitialized_memory.get(addr).unwrap_or(&0);
                memory_initialize_events.push(MemoryInitializeFinalizeEvent::initialize(
                    *addr,
                    *initial_value,
                    true,
                ));
            }

            let record = *self.state.memory.get(addr).unwrap();
            memory_finalize_events.push(MemoryInitializeFinalizeEvent::finalize_from_record(
                *addr, &record,
            ));
        }
    }

    fn get_syscall(&mut self, code: SyscallCode) -> Option<&Arc<dyn Syscall>> {
        self.syscall_map.get(&code)
    }
}

#[cfg(test)]
pub mod tests {

    use crate::{
        runtime::Register,
        utils::{
            tests::{FIBONACCI_ELF, KECCAK_PERMUTE_ELF, PANIC_ELF},
            SP1CoreOpts,
        },
    };

    use super::{Instruction, Opcode, Program, Runtime};

    pub fn simple_program() -> Program {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
        ];
        Program::new(instructions, 0, 0)
    }

    pub fn fibonacci_program() -> Program {
        Program::from(FIBONACCI_ELF)
    }

    pub fn ssz_withdrawals_program() -> Program {
        Program::from(KECCAK_PERMUTE_ELF)
    }

    pub fn panic_program() -> Program {
        Program::from(PANIC_ELF)
    }

    fn _assert_send<T: Send>() {}

    /// Runtime needs to be Send so we can use it across async calls.
    fn _assert_runtime_is_send() {
        _assert_send::<Runtime>();
    }

    #[test]
    fn test_simple_program_run() {
        let program = simple_program();
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 42);
    }

    #[test]
    #[should_panic]
    fn test_panic() {
        let program = panic_program();
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
    }

    #[test]
    fn test_add() {
        // main:
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     add x31, x30, x29
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 42);
    }

    #[test]
    fn test_sub() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sub x31, x30, x29
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::SUB, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 32);
    }

    #[test]
    fn test_xor() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     xor x31, x30, x29
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::XOR, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 32);
    }

    #[test]
    fn test_or() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     or x31, x30, x29
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::OR, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Runtime::new(program, SP1CoreOpts::default());

        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 37);
    }

    #[test]
    fn test_and() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     and x31, x30, x29
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::AND, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 5);
    }

    #[test]
    fn test_sll() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sll x31, x30, x29
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::SLL, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 1184);
    }

    #[test]
    fn test_srl() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     srl x31, x30, x29
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::SRL, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 1);
    }

    #[test]
    fn test_sra() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sra x31, x30, x29
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::SRA, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 1);
    }

    #[test]
    fn test_slt() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     slt x31, x30, x29
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::SLT, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 0);
    }

    #[test]
    fn test_sltu() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sltu x31, x30, x29
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::SLTU, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 0);
    }

    #[test]
    fn test_addi() {
        //     addi x29, x0, 5
        //     addi x30, x29, 37
        //     addi x31, x30, 42
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 29, 37, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 42, false, true),
        ];
        let program = Program::new(instructions, 0, 0);

        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 84);
    }

    #[test]
    fn test_addi_negative() {
        //     addi x29, x0, 5
        //     addi x30, x29, -1
        //     addi x31, x30, 4
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 29, 0xffffffff, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 4, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 5 - 1 + 4);
    }

    #[test]
    fn test_xori() {
        //     addi x29, x0, 5
        //     xori x30, x29, 37
        //     xori x31, x30, 42
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::XOR, 30, 29, 37, false, true),
            Instruction::new(Opcode::XOR, 31, 30, 42, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 10);
    }

    #[test]
    fn test_ori() {
        //     addi x29, x0, 5
        //     ori x30, x29, 37
        //     ori x31, x30, 42
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::OR, 30, 29, 37, false, true),
            Instruction::new(Opcode::OR, 31, 30, 42, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 47);
    }

    #[test]
    fn test_andi() {
        //     addi x29, x0, 5
        //     andi x30, x29, 37
        //     andi x31, x30, 42
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::AND, 30, 29, 37, false, true),
            Instruction::new(Opcode::AND, 31, 30, 42, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 0);
    }

    #[test]
    fn test_slli() {
        //     addi x29, x0, 5
        //     slli x31, x29, 37
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::SLL, 31, 29, 4, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 80);
    }

    #[test]
    fn test_srli() {
        //    addi x29, x0, 5
        //    srli x31, x29, 37
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 42, false, true),
            Instruction::new(Opcode::SRL, 31, 29, 4, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 2);
    }

    #[test]
    fn test_srai() {
        //   addi x29, x0, 5
        //   srai x31, x29, 37
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 42, false, true),
            Instruction::new(Opcode::SRA, 31, 29, 4, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 2);
    }

    #[test]
    fn test_slti() {
        //   addi x29, x0, 5
        //   slti x31, x29, 37
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 42, false, true),
            Instruction::new(Opcode::SLT, 31, 29, 37, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 0);
    }

    #[test]
    fn test_sltiu() {
        //   addi x29, x0, 5
        //   sltiu x31, x29, 37
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 42, false, true),
            Instruction::new(Opcode::SLTU, 31, 29, 37, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.register(Register::X31), 0);
    }

    #[test]
    fn test_jalr() {
        //   addi x11, x11, 100
        //   jalr x5, x11, 8
        //
        // `JALR rd offset(rs)` reads the value at rs, adds offset to it and uses it as the
        // destination address. It then stores the address of the next instruction in rd in case
        // we'd want to come back here.

        let instructions = vec![
            Instruction::new(Opcode::ADD, 11, 11, 100, false, true),
            Instruction::new(Opcode::JALR, 5, 11, 8, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.registers()[Register::X5 as usize], 8);
        assert_eq!(runtime.registers()[Register::X11 as usize], 100);
        assert_eq!(runtime.state.pc, 108);
    }

    fn simple_op_code_test(opcode: Opcode, expected: u32, a: u32, b: u32) {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 10, 0, a, false, true),
            Instruction::new(Opcode::ADD, 11, 0, b, false, true),
            Instruction::new(opcode, 12, 10, 11, false, false),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        assert_eq!(runtime.registers()[Register::X12 as usize], expected);
    }

    #[test]
    fn multiplication_tests() {
        simple_op_code_test(Opcode::MULHU, 0x00000000, 0x00000000, 0x00000000);
        simple_op_code_test(Opcode::MULHU, 0x00000000, 0x00000001, 0x00000001);
        simple_op_code_test(Opcode::MULHU, 0x00000000, 0x00000003, 0x00000007);
        simple_op_code_test(Opcode::MULHU, 0x00000000, 0x00000000, 0xffff8000);
        simple_op_code_test(Opcode::MULHU, 0x00000000, 0x80000000, 0x00000000);
        simple_op_code_test(Opcode::MULHU, 0x7fffc000, 0x80000000, 0xffff8000);
        simple_op_code_test(Opcode::MULHU, 0x0001fefe, 0xaaaaaaab, 0x0002fe7d);
        simple_op_code_test(Opcode::MULHU, 0x0001fefe, 0x0002fe7d, 0xaaaaaaab);
        simple_op_code_test(Opcode::MULHU, 0xfe010000, 0xff000000, 0xff000000);
        simple_op_code_test(Opcode::MULHU, 0xfffffffe, 0xffffffff, 0xffffffff);
        simple_op_code_test(Opcode::MULHU, 0x00000000, 0xffffffff, 0x00000001);
        simple_op_code_test(Opcode::MULHU, 0x00000000, 0x00000001, 0xffffffff);

        simple_op_code_test(Opcode::MULHSU, 0x00000000, 0x00000000, 0x00000000);
        simple_op_code_test(Opcode::MULHSU, 0x00000000, 0x00000001, 0x00000001);
        simple_op_code_test(Opcode::MULHSU, 0x00000000, 0x00000003, 0x00000007);
        simple_op_code_test(Opcode::MULHSU, 0x00000000, 0x00000000, 0xffff8000);
        simple_op_code_test(Opcode::MULHSU, 0x00000000, 0x80000000, 0x00000000);
        simple_op_code_test(Opcode::MULHSU, 0x80004000, 0x80000000, 0xffff8000);
        simple_op_code_test(Opcode::MULHSU, 0xffff0081, 0xaaaaaaab, 0x0002fe7d);
        simple_op_code_test(Opcode::MULHSU, 0x0001fefe, 0x0002fe7d, 0xaaaaaaab);
        simple_op_code_test(Opcode::MULHSU, 0xff010000, 0xff000000, 0xff000000);
        simple_op_code_test(Opcode::MULHSU, 0xffffffff, 0xffffffff, 0xffffffff);
        simple_op_code_test(Opcode::MULHSU, 0xffffffff, 0xffffffff, 0x00000001);
        simple_op_code_test(Opcode::MULHSU, 0x00000000, 0x00000001, 0xffffffff);

        simple_op_code_test(Opcode::MULH, 0x00000000, 0x00000000, 0x00000000);
        simple_op_code_test(Opcode::MULH, 0x00000000, 0x00000001, 0x00000001);
        simple_op_code_test(Opcode::MULH, 0x00000000, 0x00000003, 0x00000007);
        simple_op_code_test(Opcode::MULH, 0x00000000, 0x00000000, 0xffff8000);
        simple_op_code_test(Opcode::MULH, 0x00000000, 0x80000000, 0x00000000);
        simple_op_code_test(Opcode::MULH, 0x00000000, 0x80000000, 0x00000000);
        simple_op_code_test(Opcode::MULH, 0xffff0081, 0xaaaaaaab, 0x0002fe7d);
        simple_op_code_test(Opcode::MULH, 0xffff0081, 0x0002fe7d, 0xaaaaaaab);
        simple_op_code_test(Opcode::MULH, 0x00010000, 0xff000000, 0xff000000);
        simple_op_code_test(Opcode::MULH, 0x00000000, 0xffffffff, 0xffffffff);
        simple_op_code_test(Opcode::MULH, 0xffffffff, 0xffffffff, 0x00000001);
        simple_op_code_test(Opcode::MULH, 0xffffffff, 0x00000001, 0xffffffff);

        simple_op_code_test(Opcode::MUL, 0x00001200, 0x00007e00, 0xb6db6db7);
        simple_op_code_test(Opcode::MUL, 0x00001240, 0x00007fc0, 0xb6db6db7);
        simple_op_code_test(Opcode::MUL, 0x00000000, 0x00000000, 0x00000000);
        simple_op_code_test(Opcode::MUL, 0x00000001, 0x00000001, 0x00000001);
        simple_op_code_test(Opcode::MUL, 0x00000015, 0x00000003, 0x00000007);
        simple_op_code_test(Opcode::MUL, 0x00000000, 0x00000000, 0xffff8000);
        simple_op_code_test(Opcode::MUL, 0x00000000, 0x80000000, 0x00000000);
        simple_op_code_test(Opcode::MUL, 0x00000000, 0x80000000, 0xffff8000);
        simple_op_code_test(Opcode::MUL, 0x0000ff7f, 0xaaaaaaab, 0x0002fe7d);
        simple_op_code_test(Opcode::MUL, 0x0000ff7f, 0x0002fe7d, 0xaaaaaaab);
        simple_op_code_test(Opcode::MUL, 0x00000000, 0xff000000, 0xff000000);
        simple_op_code_test(Opcode::MUL, 0x00000001, 0xffffffff, 0xffffffff);
        simple_op_code_test(Opcode::MUL, 0xffffffff, 0xffffffff, 0x00000001);
        simple_op_code_test(Opcode::MUL, 0xffffffff, 0x00000001, 0xffffffff);
    }

    fn neg(a: u32) -> u32 {
        u32::MAX - a + 1
    }

    #[test]
    fn division_tests() {
        simple_op_code_test(Opcode::DIVU, 3, 20, 6);
        simple_op_code_test(Opcode::DIVU, 715827879, u32::MAX - 20 + 1, 6);
        simple_op_code_test(Opcode::DIVU, 0, 20, u32::MAX - 6 + 1);
        simple_op_code_test(Opcode::DIVU, 0, u32::MAX - 20 + 1, u32::MAX - 6 + 1);

        simple_op_code_test(Opcode::DIVU, 1 << 31, 1 << 31, 1);
        simple_op_code_test(Opcode::DIVU, 0, 1 << 31, u32::MAX - 1 + 1);

        simple_op_code_test(Opcode::DIVU, u32::MAX, 1 << 31, 0);
        simple_op_code_test(Opcode::DIVU, u32::MAX, 1, 0);
        simple_op_code_test(Opcode::DIVU, u32::MAX, 0, 0);

        simple_op_code_test(Opcode::DIV, 3, 18, 6);
        simple_op_code_test(Opcode::DIV, neg(6), neg(24), 4);
        simple_op_code_test(Opcode::DIV, neg(2), 16, neg(8));
        simple_op_code_test(Opcode::DIV, neg(1), 0, 0);

        // Overflow cases
        simple_op_code_test(Opcode::DIV, 1 << 31, 1 << 31, neg(1));
        simple_op_code_test(Opcode::REM, 0, 1 << 31, neg(1));
    }

    #[test]
    fn remainder_tests() {
        simple_op_code_test(Opcode::REM, 7, 16, 9);
        simple_op_code_test(Opcode::REM, neg(4), neg(22), 6);
        simple_op_code_test(Opcode::REM, 1, 25, neg(3));
        simple_op_code_test(Opcode::REM, neg(2), neg(22), neg(4));
        simple_op_code_test(Opcode::REM, 0, 873, 1);
        simple_op_code_test(Opcode::REM, 0, 873, neg(1));
        simple_op_code_test(Opcode::REM, 5, 5, 0);
        simple_op_code_test(Opcode::REM, neg(5), neg(5), 0);
        simple_op_code_test(Opcode::REM, 0, 0, 0);

        simple_op_code_test(Opcode::REMU, 4, 18, 7);
        simple_op_code_test(Opcode::REMU, 6, neg(20), 11);
        simple_op_code_test(Opcode::REMU, 23, 23, neg(6));
        simple_op_code_test(Opcode::REMU, neg(21), neg(21), neg(11));
        simple_op_code_test(Opcode::REMU, 5, 5, 0);
        simple_op_code_test(Opcode::REMU, neg(1), neg(1), 0);
        simple_op_code_test(Opcode::REMU, 0, 0, 0);
    }

    #[test]
    fn shift_tests() {
        simple_op_code_test(Opcode::SLL, 0x00000001, 0x00000001, 0);
        simple_op_code_test(Opcode::SLL, 0x00000002, 0x00000001, 1);
        simple_op_code_test(Opcode::SLL, 0x00000080, 0x00000001, 7);
        simple_op_code_test(Opcode::SLL, 0x00004000, 0x00000001, 14);
        simple_op_code_test(Opcode::SLL, 0x80000000, 0x00000001, 31);
        simple_op_code_test(Opcode::SLL, 0xffffffff, 0xffffffff, 0);
        simple_op_code_test(Opcode::SLL, 0xfffffffe, 0xffffffff, 1);
        simple_op_code_test(Opcode::SLL, 0xffffff80, 0xffffffff, 7);
        simple_op_code_test(Opcode::SLL, 0xffffc000, 0xffffffff, 14);
        simple_op_code_test(Opcode::SLL, 0x80000000, 0xffffffff, 31);
        simple_op_code_test(Opcode::SLL, 0x21212121, 0x21212121, 0);
        simple_op_code_test(Opcode::SLL, 0x42424242, 0x21212121, 1);
        simple_op_code_test(Opcode::SLL, 0x90909080, 0x21212121, 7);
        simple_op_code_test(Opcode::SLL, 0x48484000, 0x21212121, 14);
        simple_op_code_test(Opcode::SLL, 0x80000000, 0x21212121, 31);
        simple_op_code_test(Opcode::SLL, 0x21212121, 0x21212121, 0xffffffe0);
        simple_op_code_test(Opcode::SLL, 0x42424242, 0x21212121, 0xffffffe1);
        simple_op_code_test(Opcode::SLL, 0x90909080, 0x21212121, 0xffffffe7);
        simple_op_code_test(Opcode::SLL, 0x48484000, 0x21212121, 0xffffffee);
        simple_op_code_test(Opcode::SLL, 0x00000000, 0x21212120, 0xffffffff);

        simple_op_code_test(Opcode::SRL, 0xffff8000, 0xffff8000, 0);
        simple_op_code_test(Opcode::SRL, 0x7fffc000, 0xffff8000, 1);
        simple_op_code_test(Opcode::SRL, 0x01ffff00, 0xffff8000, 7);
        simple_op_code_test(Opcode::SRL, 0x0003fffe, 0xffff8000, 14);
        simple_op_code_test(Opcode::SRL, 0x0001ffff, 0xffff8001, 15);
        simple_op_code_test(Opcode::SRL, 0xffffffff, 0xffffffff, 0);
        simple_op_code_test(Opcode::SRL, 0x7fffffff, 0xffffffff, 1);
        simple_op_code_test(Opcode::SRL, 0x01ffffff, 0xffffffff, 7);
        simple_op_code_test(Opcode::SRL, 0x0003ffff, 0xffffffff, 14);
        simple_op_code_test(Opcode::SRL, 0x00000001, 0xffffffff, 31);
        simple_op_code_test(Opcode::SRL, 0x21212121, 0x21212121, 0);
        simple_op_code_test(Opcode::SRL, 0x10909090, 0x21212121, 1);
        simple_op_code_test(Opcode::SRL, 0x00424242, 0x21212121, 7);
        simple_op_code_test(Opcode::SRL, 0x00008484, 0x21212121, 14);
        simple_op_code_test(Opcode::SRL, 0x00000000, 0x21212121, 31);
        simple_op_code_test(Opcode::SRL, 0x21212121, 0x21212121, 0xffffffe0);
        simple_op_code_test(Opcode::SRL, 0x10909090, 0x21212121, 0xffffffe1);
        simple_op_code_test(Opcode::SRL, 0x00424242, 0x21212121, 0xffffffe7);
        simple_op_code_test(Opcode::SRL, 0x00008484, 0x21212121, 0xffffffee);
        simple_op_code_test(Opcode::SRL, 0x00000000, 0x21212121, 0xffffffff);

        simple_op_code_test(Opcode::SRA, 0x00000000, 0x00000000, 0);
        simple_op_code_test(Opcode::SRA, 0xc0000000, 0x80000000, 1);
        simple_op_code_test(Opcode::SRA, 0xff000000, 0x80000000, 7);
        simple_op_code_test(Opcode::SRA, 0xfffe0000, 0x80000000, 14);
        simple_op_code_test(Opcode::SRA, 0xffffffff, 0x80000001, 31);
        simple_op_code_test(Opcode::SRA, 0x7fffffff, 0x7fffffff, 0);
        simple_op_code_test(Opcode::SRA, 0x3fffffff, 0x7fffffff, 1);
        simple_op_code_test(Opcode::SRA, 0x00ffffff, 0x7fffffff, 7);
        simple_op_code_test(Opcode::SRA, 0x0001ffff, 0x7fffffff, 14);
        simple_op_code_test(Opcode::SRA, 0x00000000, 0x7fffffff, 31);
        simple_op_code_test(Opcode::SRA, 0x81818181, 0x81818181, 0);
        simple_op_code_test(Opcode::SRA, 0xc0c0c0c0, 0x81818181, 1);
        simple_op_code_test(Opcode::SRA, 0xff030303, 0x81818181, 7);
        simple_op_code_test(Opcode::SRA, 0xfffe0606, 0x81818181, 14);
        simple_op_code_test(Opcode::SRA, 0xffffffff, 0x81818181, 31);
    }

    pub fn simple_memory_program() -> Program {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 0x12348765, false, true),
            // SW and LW
            Instruction::new(Opcode::SW, 29, 0, 0x27654320, false, true),
            Instruction::new(Opcode::LW, 28, 0, 0x27654320, false, true),
            // LBU
            Instruction::new(Opcode::LBU, 27, 0, 0x27654320, false, true),
            Instruction::new(Opcode::LBU, 26, 0, 0x27654321, false, true),
            Instruction::new(Opcode::LBU, 25, 0, 0x27654322, false, true),
            Instruction::new(Opcode::LBU, 24, 0, 0x27654323, false, true),
            // LB
            Instruction::new(Opcode::LB, 23, 0, 0x27654320, false, true),
            Instruction::new(Opcode::LB, 22, 0, 0x27654321, false, true),
            // LHU
            Instruction::new(Opcode::LHU, 21, 0, 0x27654320, false, true),
            Instruction::new(Opcode::LHU, 20, 0, 0x27654322, false, true),
            // LU
            Instruction::new(Opcode::LH, 19, 0, 0x27654320, false, true),
            Instruction::new(Opcode::LH, 18, 0, 0x27654322, false, true),
            // SB
            Instruction::new(Opcode::ADD, 17, 0, 0x38276525, false, true),
            // Save the value 0x12348765 into address 0x43627530
            Instruction::new(Opcode::SW, 29, 0, 0x43627530, false, true),
            Instruction::new(Opcode::SB, 17, 0, 0x43627530, false, true),
            Instruction::new(Opcode::LW, 16, 0, 0x43627530, false, true),
            Instruction::new(Opcode::SB, 17, 0, 0x43627531, false, true),
            Instruction::new(Opcode::LW, 15, 0, 0x43627530, false, true),
            Instruction::new(Opcode::SB, 17, 0, 0x43627532, false, true),
            Instruction::new(Opcode::LW, 14, 0, 0x43627530, false, true),
            Instruction::new(Opcode::SB, 17, 0, 0x43627533, false, true),
            Instruction::new(Opcode::LW, 13, 0, 0x43627530, false, true),
            // SH
            // Save the value 0x12348765 into address 0x43627530
            Instruction::new(Opcode::SW, 29, 0, 0x43627530, false, true),
            Instruction::new(Opcode::SH, 17, 0, 0x43627530, false, true),
            Instruction::new(Opcode::LW, 12, 0, 0x43627530, false, true),
            Instruction::new(Opcode::SH, 17, 0, 0x43627532, false, true),
            Instruction::new(Opcode::LW, 11, 0, 0x43627530, false, true),
        ];
        Program::new(instructions, 0, 0)
    }

    #[test]
    fn test_simple_memory_program_run() {
        let program = simple_memory_program();
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();

        // Assert SW & LW case
        assert_eq!(runtime.register(Register::X28), 0x12348765);

        // Assert LBU cases
        assert_eq!(runtime.register(Register::X27), 0x65);
        assert_eq!(runtime.register(Register::X26), 0x87);
        assert_eq!(runtime.register(Register::X25), 0x34);
        assert_eq!(runtime.register(Register::X24), 0x12);

        // Assert LB cases
        assert_eq!(runtime.register(Register::X23), 0x65);
        assert_eq!(runtime.register(Register::X22), 0xffffff87);

        // Assert LHU cases
        assert_eq!(runtime.register(Register::X21), 0x8765);
        assert_eq!(runtime.register(Register::X20), 0x1234);

        // Assert LH cases
        assert_eq!(runtime.register(Register::X19), 0xffff8765);
        assert_eq!(runtime.register(Register::X18), 0x1234);

        // Assert SB cases
        assert_eq!(runtime.register(Register::X16), 0x12348725);
        assert_eq!(runtime.register(Register::X15), 0x12342525);
        assert_eq!(runtime.register(Register::X14), 0x12252525);
        assert_eq!(runtime.register(Register::X13), 0x25252525);

        // Assert SH cases
        assert_eq!(runtime.register(Register::X12), 0x12346525);
        assert_eq!(runtime.register(Register::X11), 0x65256525);
    }
}
