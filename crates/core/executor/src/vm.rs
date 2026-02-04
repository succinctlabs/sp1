#![allow(unknown_lints)]
#![allow(clippy::manual_checked_ops)]

use crate::{
    events::{MemoryAccessPosition, MemoryReadRecord, MemoryRecord, MemoryWriteRecord},
    vm::{
        results::{
            AluResult, BranchResult, CycleResult, EcallResult, JumpResult, LoadResult,
            MaybeImmediate, StoreResult, UTypeResult,
        },
        syscall::{sp1_ecall_handler, SyscallRuntime},
    },
    ExecutionError, Instruction, Opcode, Program, Register, RetainedEventsPreset, SP1CoreOpts,
    SyscallCode, CLK_INC as CLK_INC_32, HALT_PC, PC_INC as PC_INC_32,
};
use sp1_hypercube::air::{PROOF_NONCE_NUM_WORDS, PV_DIGEST_NUM_WORDS};
use sp1_jit::{MemReads, MinimalTrace};
use std::{mem::MaybeUninit, num::Wrapping, ptr::addr_of_mut, sync::Arc};

pub(crate) mod gas;
pub(crate) mod memory;
pub(crate) mod results;
pub(crate) mod shapes;
pub(crate) mod syscall;

const CLK_INC: u64 = CLK_INC_32 as u64;
const PC_INC: u64 = PC_INC_32 as u64;

/// A RISC-V VM that uses a [`MinimalTrace`] to oracle memory access.
pub struct CoreVM<'a> {
    registers: [MemoryRecord; 32],
    /// The current clock of the VM.
    clk: u64,
    /// The global clock of the VM.
    global_clk: u64,
    /// The current program counter of the VM.
    pc: u64,
    /// The current exit code of the VM.
    exit_code: u32,
    /// The memory reads cursoir.
    pub mem_reads: MemReads<'a>,
    /// The next program counter that will be set in [`CoreVM::advance`].
    next_pc: u64,
    /// The next clock that will be set in [`CoreVM::advance`].
    next_clk: u64,
    /// The hint lenghts that read from within the vm.
    hint_lens: std::slice::Iter<'a, usize>,
    /// The program that is being executed.
    pub program: Arc<Program>,
    /// The syscalls that are not marked as external, ie. they stay in the same shard.
    pub(crate) retained_syscall_codes: Vec<SyscallCode>,
    /// The options to configure the VM, mostly for syscall / shard handling.
    pub opts: SP1CoreOpts,
    /// The end clk of the trace chunk.
    pub clk_end: u64,
    /// The public value digest.
    pub public_value_digest: [u32; PV_DIGEST_NUM_WORDS],
    /// The nonce associated with the proof.
    pub proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
}

impl<'a> CoreVM<'a> {
    /// Create a [`CoreVM`] from a [`MinimalTrace`] and a [`Program`].
    pub fn new<T: MinimalTrace>(
        trace: &'a T,
        program: Arc<Program>,
        opts: SP1CoreOpts,
        proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
    ) -> Self {
        let start_clk = trace.clk_start();

        // SAFETY: We're mapping a [T; 32] -> [T; 32] infallibly.
        let registers = unsafe {
            trace
                .start_registers()
                .into_iter()
                .map(|v| MemoryRecord { timestamp: start_clk - 1, value: v })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap_unchecked()
        };
        let start_pc = trace.pc_start();

        let retained_syscall_codes = opts
            .retained_events_presets
            .iter()
            .flat_map(RetainedEventsPreset::syscall_codes)
            .copied()
            .collect();

        tracing::trace!("start_clk: {}", start_clk);
        tracing::trace!("start_pc: {}", start_pc);
        tracing::trace!("trace.clk_end(): {}", trace.clk_end());
        tracing::trace!("trace.num_mem_reads(): {}", trace.num_mem_reads());
        tracing::trace!("trace.hint_lens(): {:?}", trace.hint_lens().len());
        tracing::trace!("trace.start_registers(): {:?}", trace.start_registers());

        if trace.clk_start() == 1 {
            assert_eq!(trace.pc_start(), program.pc_start_abs);
        }

        Self {
            registers,
            global_clk: 0,
            clk: start_clk,
            pc: start_pc,
            program,
            mem_reads: trace.mem_reads(),
            next_pc: start_pc.wrapping_add(PC_INC),
            next_clk: start_clk.wrapping_add(CLK_INC),
            hint_lens: trace.hint_lens().iter(),
            exit_code: 0,
            retained_syscall_codes,
            opts,
            clk_end: trace.clk_end(),
            public_value_digest: [0; PV_DIGEST_NUM_WORDS],
            proof_nonce,
        }
    }

    /// Fetch the next instruction from the program.
    #[inline]
    pub fn fetch(&mut self) -> Option<&Instruction> {
        // todo: mprotect / kernel mode logic.
        self.program.fetch(self.pc)
    }

    #[inline]
    /// Increment the state of the VM by one cycle.
    /// Calling this method will update the pc and the clk to the next cycle.
    pub fn advance(&mut self) -> CycleResult {
        self.clk = self.next_clk;
        self.pc = self.next_pc;

        // Reset the next_clk and next_pc to the next cycle.
        self.next_clk = self.clk.wrapping_add(CLK_INC);
        self.next_pc = self.pc.wrapping_add(PC_INC);
        self.global_clk = self.global_clk.wrapping_add(1);

        // Check if the program has halted.
        if self.pc == HALT_PC {
            return CycleResult::Done(true);
        }

        // Check if the shard limit has been reached.
        if self.is_trace_end() {
            return CycleResult::TraceEnd;
        }

        // Return that the program is still running.
        CycleResult::Done(false)
    }

    /// Execute a load instruction.
    #[inline]
    pub fn execute_load(
        &mut self,
        instruction: &Instruction,
    ) -> Result<LoadResult, ExecutionError> {
        let (rd, rs1, imm) = instruction.i_type();

        let rr_record = self.rr(rs1, MemoryAccessPosition::B);
        let b = rr_record.value;

        // Compute the address.
        let addr = b.wrapping_add(imm);
        let mr_record = self.mr(addr);
        let word = mr_record.value;

        let a = match instruction.opcode {
            Opcode::LB => ((word >> ((addr % 8) * 8)) & 0xFF) as i8 as i64 as u64,
            Opcode::LH => {
                if !addr.is_multiple_of(2) {
                    return Err(ExecutionError::InvalidMemoryAccess(Opcode::LH, addr));
                }

                ((word >> (((addr / 2) % 4) * 16)) & 0xFFFF) as i16 as i64 as u64
            }
            Opcode::LW => {
                if !addr.is_multiple_of(4) {
                    return Err(ExecutionError::InvalidMemoryAccess(Opcode::LW, addr));
                }

                ((word >> (((addr / 4) % 2) * 32)) & 0xFFFFFFFF) as i32 as u64
            }
            Opcode::LBU => ((word >> ((addr % 8) * 8)) & 0xFF) as u8 as u64,
            Opcode::LHU => {
                if !addr.is_multiple_of(2) {
                    return Err(ExecutionError::InvalidMemoryAccess(Opcode::LHU, addr));
                }

                ((word >> (((addr / 2) % 4) * 16)) & 0xFFFF) as u16 as u64
            }
            // RISCV-64
            Opcode::LWU => {
                if !addr.is_multiple_of(4) {
                    return Err(ExecutionError::InvalidMemoryAccess(Opcode::LWU, addr));
                }

                (word >> (((addr / 4) % 2) * 32)) & 0xFFFFFFFF
            }
            Opcode::LD => {
                if !addr.is_multiple_of(8) {
                    return Err(ExecutionError::InvalidMemoryAccess(Opcode::LD, addr));
                }

                word
            }
            _ => unreachable!("Invalid opcode for `execute_load`: {:?}", instruction.opcode),
        };

        let rw_record = self.rw(rd, a);

        Ok(LoadResult { a, b, c: imm, addr, rs1, rd, rr_record, rw_record, mr_record })
    }

    /// Execute a store instruction.
    #[inline]
    pub fn execute_store(
        &mut self,
        instruction: &Instruction,
    ) -> Result<StoreResult, ExecutionError> {
        let (rs1, rs2, imm) = instruction.s_type();

        let c = imm;
        let rs2_record = self.rr(rs2, MemoryAccessPosition::B);
        let rs1_record = self.rr(rs1, MemoryAccessPosition::A);

        let b = rs2_record.value;
        let a = rs1_record.value;
        let addr = b.wrapping_add(c);
        let mr_record = self.mr(addr);
        let word = mr_record.value;

        let memory_store_value = match instruction.opcode {
            Opcode::SB => {
                let shift = (addr % 8) * 8;
                ((a & 0xFF) << shift) | (word & !(0xFF << shift))
            }
            Opcode::SH => {
                if !addr.is_multiple_of(2) {
                    return Err(ExecutionError::InvalidMemoryAccess(Opcode::SH, addr));
                }
                let shift = ((addr / 2) % 4) * 16;
                ((a & 0xFFFF) << shift) | (word & !(0xFFFF << shift))
            }
            Opcode::SW => {
                if !addr.is_multiple_of(4) {
                    return Err(ExecutionError::InvalidMemoryAccess(Opcode::SW, addr));
                }
                let shift = ((addr / 4) % 2) * 32;
                ((a & 0xFFFFFFFF) << shift) | (word & !(0xFFFFFFFF << shift))
            }
            // RISCV-64
            Opcode::SD => {
                if !addr.is_multiple_of(8) {
                    return Err(ExecutionError::InvalidMemoryAccess(Opcode::SD, addr));
                }
                a
            }
            _ => unreachable!(),
        };

        let mw_record = self.mw(mr_record, memory_store_value);

        Ok(StoreResult { a, b, c, addr, rs1, rs1_record, rs2, rs2_record, mw_record })
    }

    /// Execute an ALU instruction.
    #[inline]
    #[allow(clippy::too_many_lines)]
    pub fn execute_alu(&mut self, instruction: &Instruction) -> AluResult {
        let mut result = MaybeUninit::<AluResult>::uninit();
        let result_ptr = result.as_mut_ptr();

        let (rd, b, c) = if !instruction.imm_c {
            let (rd, rs1, rs2) = instruction.r_type();
            let c = self.rr(rs2, MemoryAccessPosition::C);
            let b = self.rr(rs1, MemoryAccessPosition::B);

            // SAFETY: We're writing to a valid pointer as we just created the pointer from the
            // `result`.
            unsafe { addr_of_mut!((*result_ptr).rs1).write(MaybeImmediate::Register(rs1, b)) };
            unsafe { addr_of_mut!((*result_ptr).rs2).write(MaybeImmediate::Register(rs2, c)) };

            (rd, b.value, c.value)
        } else if !instruction.imm_b && instruction.imm_c {
            let (rd, rs1, imm) = instruction.i_type();
            let (rd, b, c) = (rd, self.rr(rs1, MemoryAccessPosition::B), imm);

            // SAFETY: We're writing to a valid pointer as we just created the pointer from the
            // `result`.
            unsafe { addr_of_mut!((*result_ptr).rs1).write(MaybeImmediate::Register(rs1, b)) };
            unsafe { addr_of_mut!((*result_ptr).rs2).write(MaybeImmediate::Immediate(c)) };

            (rd, b.value, c)
        } else {
            debug_assert!(instruction.imm_b && instruction.imm_c);
            let (rd, b, c) =
                (Register::from_u8(instruction.op_a), instruction.op_b, instruction.op_c);

            // SAFETY: We're writing to a valid pointer as we just created the pointer from the
            // `result`.
            unsafe { addr_of_mut!((*result_ptr).rs1).write(MaybeImmediate::Immediate(b)) };
            unsafe { addr_of_mut!((*result_ptr).rs2).write(MaybeImmediate::Immediate(c)) };

            (rd, b, c)
        };

        let a = match instruction.opcode {
            Opcode::ADD | Opcode::ADDI => (Wrapping(b) + Wrapping(c)).0,
            Opcode::SUB => (Wrapping(b) - Wrapping(c)).0,
            Opcode::XOR => b ^ c,
            Opcode::OR => b | c,
            Opcode::AND => b & c,
            Opcode::SLL => b << (c & 0x3f),
            Opcode::SRL => b >> (c & 0x3f),
            Opcode::SRA => ((b as i64) >> (c & 0x3f)) as u64,
            Opcode::SLT => {
                if (b as i64) < (c as i64) {
                    1
                } else {
                    0
                }
            }
            Opcode::SLTU => {
                if b < c {
                    1
                } else {
                    0
                }
            }
            Opcode::MUL => (Wrapping(b as i64) * Wrapping(c as i64)).0 as u64,
            Opcode::MULH => (((b as i64) as i128).wrapping_mul((c as i64) as i128) >> 64) as u64,
            Opcode::MULHU => ((b as u128 * c as u128) >> 64) as u64,
            Opcode::MULHSU => ((((b as i64) as i128) * (c as i128)) >> 64) as u64,
            Opcode::DIV => {
                if c == 0 {
                    u64::MAX
                } else {
                    (b as i64).wrapping_div(c as i64) as u64
                }
            }
            Opcode::DIVU => {
                if c == 0 {
                    u64::MAX
                } else {
                    b / c
                }
            }
            Opcode::REM => {
                if c == 0 {
                    b
                } else {
                    (b as i64).wrapping_rem(c as i64) as u64
                }
            }
            Opcode::REMU => {
                if c == 0 {
                    b
                } else {
                    b % c
                }
            }
            // RISCV-64 word operations
            Opcode::ADDW => (Wrapping(b as i32) + Wrapping(c as i32)).0 as i64 as u64,
            Opcode::SUBW => (Wrapping(b as i32) - Wrapping(c as i32)).0 as i64 as u64,
            Opcode::MULW => (Wrapping(b as i32) * Wrapping(c as i32)).0 as i64 as u64,
            Opcode::DIVW => {
                if c as i32 == 0 {
                    u64::MAX
                } else {
                    (b as i32).wrapping_div(c as i32) as i64 as u64
                }
            }
            Opcode::DIVUW => {
                if c as i32 == 0 {
                    u64::MAX
                } else {
                    ((b as u32 / c as u32) as i32) as i64 as u64
                }
            }
            Opcode::REMW => {
                if c as i32 == 0 {
                    (b as i32) as u64
                } else {
                    (b as i32).wrapping_rem(c as i32) as i64 as u64
                }
            }
            Opcode::REMUW => {
                if c as u32 == 0 {
                    (b as i32) as u64
                } else {
                    (((b as u32) % (c as u32)) as i32) as i64 as u64
                }
            }
            // RISCV-64 bit operations
            Opcode::SLLW => (((b as i64) << (c & 0x1f)) as i32) as i64 as u64,
            Opcode::SRLW => (((b as u32) >> ((c & 0x1f) as u32)) as i32) as u64,
            Opcode::SRAW => {
                (b as i32).wrapping_shr(((c as i64 & 0x1f) as i32) as u32) as i64 as u64
            }
            _ => unreachable!(),
        };

        let rw_record = self.rw(rd, a);

        // SAFETY: We're writing to a valid pointer as we just created the pointer from the
        // `result`.
        unsafe { addr_of_mut!((*result_ptr).a).write(a) };
        unsafe { addr_of_mut!((*result_ptr).b).write(b) };
        unsafe { addr_of_mut!((*result_ptr).c).write(c) };
        unsafe { addr_of_mut!((*result_ptr).rd).write(rd) };
        unsafe { addr_of_mut!((*result_ptr).rw_record).write(rw_record) };

        // SAFETY: All fields have been initialized by this point.
        unsafe { result.assume_init() }
    }

    /// Execute a jump instruction.
    pub fn execute_jump(&mut self, instruction: &Instruction) -> JumpResult {
        match instruction.opcode {
            Opcode::JAL => {
                let (rd, imm) = instruction.j_type();
                let imm_se = sign_extend_imm(imm, 21);
                let a = self.pc.wrapping_add(4);
                let rd_record = self.rw(rd, a);

                let next_pc = ((self.pc as i64).wrapping_add(imm_se)) as u64;
                let b = imm_se as u64;
                let c = 0;

                self.next_pc = next_pc;

                JumpResult { a, b, c, rd, rd_record, rs1: MaybeImmediate::Immediate(b) }
            }
            Opcode::JALR => {
                let (rd, rs1, c) = instruction.i_type();
                let imm_se = sign_extend_imm(c, 12);
                let b_record = self.rr(rs1, MemoryAccessPosition::B);
                let a = self.pc.wrapping_add(4);

                // Calculate next PC: (rs1 + imm) & ~1
                let next_pc = ((b_record.value as i64).wrapping_add(imm_se) as u64) & !1_u64;
                let rd_record = self.rw(rd, a);

                self.next_pc = next_pc;

                JumpResult {
                    a,
                    b: b_record.value,
                    c,
                    rd,
                    rd_record,
                    rs1: MaybeImmediate::Register(rs1, b_record),
                }
            }
            _ => unreachable!("Invalid opcode for `execute_jump`: {:?}", instruction.opcode),
        }
    }

    /// Execute a branch instruction.
    pub fn execute_branch(&mut self, instruction: &Instruction) -> BranchResult {
        let (rs1, rs2, imm) = instruction.b_type();

        let c = imm;
        let b_record = self.rr(rs2, MemoryAccessPosition::B);
        let a_record = self.rr(rs1, MemoryAccessPosition::A);

        let a = a_record.value;
        let b = b_record.value;

        let branch = match instruction.opcode {
            Opcode::BEQ => a == b,
            Opcode::BNE => a != b,
            Opcode::BLT => (a as i64) < (b as i64),
            Opcode::BGE => (a as i64) >= (b as i64),
            Opcode::BLTU => a < b,
            Opcode::BGEU => a >= b,
            _ => {
                unreachable!()
            }
        };

        if branch {
            self.next_pc = self.pc.wrapping_add(c);
        }

        BranchResult { a, rs1, a_record, b, rs2, b_record, c }
    }

    /// Execute a U-type instruction.
    #[inline]
    pub fn execute_utype(&mut self, instruction: &Instruction) -> UTypeResult {
        let (rd, imm) = instruction.u_type();
        let (b, c) = (imm, imm);
        let a = if instruction.opcode == Opcode::AUIPC { self.pc.wrapping_add(imm) } else { imm };
        let a_record = self.rw(rd, a);

        UTypeResult { a, b, c, rd, rw_record: a_record }
    }

    #[inline]
    /// Execute an ecall instruction.
    ///
    /// # WARNING:
    ///
    /// Its up to the syscall handler to update the shape checker abouut sent/internal ecalls.
    pub fn execute_ecall<RT>(
        rt: &mut RT,
        instruction: &Instruction,
        code: SyscallCode,
    ) -> Result<EcallResult, ExecutionError>
    where
        RT: SyscallRuntime<'a>,
    {
        if !instruction.is_ecall_instruction() {
            unreachable!("Invalid opcode for `execute_ecall`: {:?}", instruction.opcode);
        }

        let core = rt.core_mut();

        let c_record = core.rr(Register::X11, MemoryAccessPosition::C);
        let b_record = core.rr(Register::X10, MemoryAccessPosition::B);
        let c = c_record.value;
        let b = b_record.value;

        // The only way unconstrained mode interacts with the parts of the program that proven is
        // via hints, this means during tracing and splicing, we can just "skip" the whole
        // set of unconstrained cycles, and rely on the fact that the hints are already
        // apart of the minimal trace.
        let a = if code == SyscallCode::ENTER_UNCONSTRAINED {
            0
        } else {
            sp1_ecall_handler(rt, code, b, c).unwrap_or(code as u64)
        };

        // Bad borrow checker!
        let core = rt.core_mut();

        // Read the code from the x5 register.
        let a_record = core.rw(Register::X5, a);

        // Add 256 to the next clock to account for the ecall.
        core.set_next_clk(core.next_clk() + 256);

        Ok(EcallResult { a, a_record, b, b_record, c, c_record })
    }

    /// Peek to get the code from the x5 register.
    #[must_use]
    pub fn read_code(&self) -> SyscallCode {
        // We peek at register x5 to get the syscall id. The reason we don't `self.rr` this
        // register is that we write to it later.
        let t0 = Register::X5;

        // Peek at the register, we dont care about the read here.
        let syscall_id = self.registers[t0 as usize].value;

        // Convert the raw value to a SyscallCode.
        SyscallCode::from_u32(syscall_id as u32)
    }
}

impl CoreVM<'_> {
    /// Read the next required memory read from the trace.
    #[inline]
    fn mr(&mut self, addr: u64) -> MemoryReadRecord {
        #[allow(clippy::manual_let_else)]
        let record = match self.mem_reads.next() {
            Some(next) => next,
            None => {
                unreachable!("memory reads unexpectdely exhausted at {addr}, clk {}", self.clk);
            }
        };

        MemoryReadRecord {
            value: record.value,
            timestamp: self.timestamp(MemoryAccessPosition::Memory),
            prev_timestamp: record.clk,
            prev_page_prot_record: None,
        }
    }

    #[inline]
    pub(crate) fn mr_slice_unsafe(&mut self, len: usize) -> Vec<u64> {
        let mem_reads = self.mem_reads();

        mem_reads.take(len).map(|value| value.value).collect()
    }

    #[inline]
    pub(crate) fn mr_slice(&mut self, _addr: u64, len: usize) -> Vec<MemoryReadRecord> {
        let current_clk = self.clk();
        let mem_reads = self.mem_reads();

        let records: Vec<MemoryReadRecord> = mem_reads
            .take(len)
            .map(|value| MemoryReadRecord {
                value: value.value,
                timestamp: current_clk,
                prev_timestamp: value.clk,
                prev_page_prot_record: None,
            })
            .collect();

        records
    }

    #[inline]
    pub(crate) fn mw_slice(&mut self, _addr: u64, len: usize) -> Vec<MemoryWriteRecord> {
        let mem_writes = self.mem_reads();

        let raw_records: Vec<_> = mem_writes.take(len * 2).collect();
        let records: Vec<MemoryWriteRecord> = raw_records
            .chunks(2)
            .map(|chunk| {
                #[allow(clippy::manual_let_else)]
                let (old, new) = match (chunk.first(), chunk.last()) {
                    (Some(old), Some(new)) => (old, new),
                    _ => unreachable!("Precompile memory write out of bounds"),
                };

                MemoryWriteRecord {
                    prev_timestamp: old.clk,
                    prev_value: old.value,
                    timestamp: new.clk,
                    value: new.value,
                    prev_page_prot_record: None,
                }
            })
            .collect();

        records
    }

    #[inline]
    fn mw(&mut self, read_record: MemoryReadRecord, value: u64) -> MemoryWriteRecord {
        MemoryWriteRecord {
            prev_timestamp: read_record.prev_timestamp,
            prev_value: read_record.value,
            timestamp: self.timestamp(MemoryAccessPosition::Memory),
            value,
            prev_page_prot_record: None,
        }
    }

    /// Read a value from a register, updating the register entry and returning the record.
    #[inline]
    fn rr(&mut self, register: Register, position: MemoryAccessPosition) -> MemoryReadRecord {
        let prev_record = self.registers[register as usize];
        let new_record =
            MemoryRecord { timestamp: self.timestamp(position), value: prev_record.value };

        self.registers[register as usize] = new_record;

        MemoryReadRecord {
            value: new_record.value,
            timestamp: new_record.timestamp,
            prev_timestamp: prev_record.timestamp,
            prev_page_prot_record: None,
        }
    }

    /// Read a value from a register, updating the register entry and returning the record.
    #[inline]
    fn rr_precompile(&mut self, register: usize) -> MemoryReadRecord {
        debug_assert!(register < 32, "out of bounds register: {register}");

        let prev_record = self.registers[register];
        let new_record = MemoryRecord { timestamp: self.clk(), value: prev_record.value };

        self.registers[register] = new_record;

        MemoryReadRecord {
            value: new_record.value,
            timestamp: new_record.timestamp,
            prev_timestamp: prev_record.timestamp,
            prev_page_prot_record: None,
        }
    }

    /// Touch all the registers in the VM, bumping thier clock to `self.clk - 1`.
    pub fn register_refresh(&mut self) -> [MemoryReadRecord; 32] {
        fn bump_register(vm: &mut CoreVM, register: usize) -> MemoryReadRecord {
            let prev_record = vm.registers[register];
            let new_record = MemoryRecord { timestamp: vm.clk - 1, value: prev_record.value };

            vm.registers[register] = new_record;

            MemoryReadRecord {
                value: new_record.value,
                timestamp: new_record.timestamp,
                prev_timestamp: prev_record.timestamp,
                prev_page_prot_record: None,
            }
        }

        tracing::trace!("register refresh to: {}", self.clk - 1);

        let mut out = [MaybeUninit::uninit(); 32];
        for (i, record) in out.iter_mut().enumerate() {
            *record = MaybeUninit::new(bump_register(self, i));
        }

        // SAFETY: We're transmuting a [MaybeUninit<MemoryReadRecord>; 32] to a [MemoryReadRecord;
        // 32], which we just initialized.
        //
        // These types are guaranteed to have the same representation.
        unsafe { std::mem::transmute(out) }
    }

    /// Write a value to a register, updating the register entry and returning the record.
    #[inline]
    fn rw(&mut self, register: Register, value: u64) -> MemoryWriteRecord {
        let value = if register == Register::X0 { 0 } else { value };

        let prev_record = self.registers[register as usize];
        let new_record = MemoryRecord { timestamp: self.timestamp(MemoryAccessPosition::A), value };

        self.registers[register as usize] = new_record;

        // if SHAPE_CHECKING {
        //     self.shape_checker.handle_mem_event(register as u64, prev_record.timestamp);
        // }

        // if REPORT_GENERATING {
        //     self.gas_calculator.handle_mem_event(register as u64, prev_record.timestamp);
        // }

        MemoryWriteRecord {
            value: new_record.value,
            timestamp: new_record.timestamp,
            prev_timestamp: prev_record.timestamp,
            prev_value: prev_record.value,
            prev_page_prot_record: None,
        }
    }
}

impl CoreVM<'_> {
    /// Get the current timestamp for a given memory access position.
    #[inline]
    #[must_use]
    pub const fn timestamp(&self, position: MemoryAccessPosition) -> u64 {
        self.clk + position as u64
    }

    /// Check if the top 24 bits have changed, which imply a `state bump` event needs to be emitted.
    #[inline]
    #[must_use]
    pub const fn needs_bump_clk_high(&self) -> bool {
        (self.next_clk() >> 24) ^ (self.clk() >> 24) > 0
    }

    /// Check if the state needs to be bumped, which implies a `state bump` event needs to be
    /// emitted.
    #[inline]
    #[must_use]
    pub const fn needs_state_bump(&self, instruction: &Instruction) -> bool {
        let next_pc = self.next_pc();
        let increment = self.next_clk() + 8 - self.clk();

        let bump1 = self.clk() % (1 << 24) + increment >= (1 << 24);
        let bump2 = !instruction.is_with_correct_next_pc()
            && next_pc == self.pc().wrapping_add(4)
            && (next_pc >> 16) != (self.pc() >> 16);

        bump1 || bump2
    }
}

impl<'a> CoreVM<'a> {
    #[inline]
    #[must_use]
    /// Get the current clock, this clock is incremented by [`CLK_INC`] each cycle.
    pub const fn clk(&self) -> u64 {
        self.clk
    }

    #[inline]
    /// Set the current clock.
    pub fn set_clk(&mut self, new_clk: u64) {
        self.clk = new_clk;
    }

    #[inline]
    /// Set the next clock.
    pub fn set_next_clk(&mut self, clk: u64) {
        self.next_clk = clk;
    }

    #[inline]
    #[must_use]
    /// Get the global clock, this clock is incremented by 1 each cycle.
    pub fn global_clk(&self) -> u64 {
        self.global_clk
    }

    #[inline]
    #[must_use]
    /// Get the current program counter.
    pub const fn pc(&self) -> u64 {
        self.pc
    }

    #[inline]
    #[must_use]
    /// Get the next program counter that will be set in [`CoreVM::advance`].
    pub const fn next_pc(&self) -> u64 {
        self.next_pc
    }

    #[inline]
    /// Set the next program counter.
    pub fn set_next_pc(&mut self, pc: u64) {
        self.next_pc = pc;
    }

    #[inline]
    #[must_use]
    /// Get the exit code.
    pub fn exit_code(&self) -> u32 {
        self.exit_code
    }

    #[inline]
    /// Set the exit code.
    pub fn set_exit_code(&mut self, exit_code: u32) {
        self.exit_code = exit_code;
    }

    #[inline]
    /// Set the program counter.
    pub fn set_pc(&mut self, pc: u64) {
        self.pc = pc;
    }

    #[inline]
    /// Set the global clock.
    pub fn set_global_clk(&mut self, global_clk: u64) {
        self.global_clk = global_clk;
    }

    #[inline]
    #[must_use]
    /// Get the next clock that will be set in [`CoreVM::advance`].
    pub const fn next_clk(&self) -> u64 {
        self.next_clk
    }

    #[inline]
    #[must_use]
    /// Get the current registers (immutable).
    pub fn registers(&self) -> &[MemoryRecord; 32] {
        &self.registers
    }

    #[inline]
    #[must_use]
    /// Get the current registers (mutable).
    pub fn registers_mut(&mut self) -> &mut [MemoryRecord; 32] {
        &mut self.registers
    }

    #[inline]
    /// Get the memory reads iterator.
    pub fn mem_reads(&mut self) -> &mut MemReads<'a> {
        &mut self.mem_reads
    }

    /// Check if the syscall is retained.
    #[inline]
    #[must_use]
    pub fn is_retained_syscall(&self, syscall_code: SyscallCode) -> bool {
        self.retained_syscall_codes.contains(&syscall_code)
    }

    /// Check if the trace has ended.
    #[inline]
    #[must_use]
    pub const fn is_trace_end(&self) -> bool {
        self.clk_end == self.clk()
    }

    /// Check if the program has halted.
    #[inline]
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.pc() == HALT_PC
    }
}

fn sign_extend_imm(value: u64, bits: u8) -> i64 {
    let shift = 64 - bits;
    ((value as i64) << shift) >> shift
}
