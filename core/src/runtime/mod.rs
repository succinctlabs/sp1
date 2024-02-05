mod instruction;
mod io;
mod opcode;
mod program;
mod register;
mod segment;
mod syscall;

use crate::cpu::{MemoryReadRecord, MemoryRecord, MemoryRecordEnum, MemoryWriteRecord};
use crate::precompiles::edwards::ed_add::EdAddAssignChip;
use crate::precompiles::edwards::ed_decompress::EdDecompressChip;
use crate::precompiles::k256::decompress::K256DecompressChip;
use crate::precompiles::keccak256::KeccakPermuteChip;
use crate::precompiles::sha256::{ShaCompressChip, ShaExtendChip};
use crate::precompiles::weierstrass::weierstrass_add::WeierstrassAddAssignChip;
use crate::precompiles::weierstrass::weierstrass_double::WeierstrassDoubleAssignChip;
use crate::precompiles::PrecompileRuntime;
use crate::utils::ec::edwards::ed25519::Ed25519Parameters;
use crate::utils::ec::edwards::EdwardsCurve;
use crate::utils::ec::weierstrass::secp256k1::Secp256k1Parameters;
use crate::utils::ec::weierstrass::SWCurve;
use crate::utils::u32_to_comma_separated;
use crate::{alu::AluEvent, cpu::CpuEvent};
pub use instruction::*;
use nohash_hasher::BuildNoHashHasher;
pub use opcode::*;
pub use program::*;
pub use register::*;
pub use segment::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;
use std::io::Write;
use std::process::exit;
use std::sync::Arc;
pub use syscall::*;

use p3_baby_bear::BabyBear;
use p3_field::AbstractField;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AccessPosition {
    Memory = 0,
    // Note that these AccessPositions mean that when when read/writing registers, they must be
    // read/written in the following order: C, B, A.
    C = 1,
    B = 2,
    A = 3,
}

#[derive(Debug, Copy, Clone, Default)]
pub struct Record {
    pub a: Option<MemoryRecordEnum>,
    pub b: Option<MemoryRecordEnum>,
    pub c: Option<MemoryRecordEnum>,
    pub memory: Option<MemoryRecordEnum>,
}

/// An implementation of a runtime for the Curta VM.
///
/// The runtime is responsible for executing a user program and tracing important events which occur
/// during execution (i.e., memory reads, alu operations, etc).
///
/// For more information on the RV32IM instruction set, see the following:
/// https://www.cs.sfu.ca/~ashriram/Courses/CS295/assets/notebooks/RISCV/RISCV_CARD.pdf
#[derive(Debug)]
pub struct Runtime {
    /// The global clock keeps track of how many instrutions have been executed through all segments.
    pub global_clk: u32,

    /// The clock keeps track of how many instructions have been executed in this segment.
    pub clk: u32,

    /// The program counter.
    pub pc: u32,

    /// The program.
    pub program: Arc<Program>,

    /// The memory which instructions operate over.
    pub memory: HashMap<u32, u32, BuildNoHashHasher<u32>>,

    /// Maps a memory address to (segment, timestamp) that it was touched.
    pub memory_access: HashMap<u32, (u32, u32), BuildNoHashHasher<u32>>,

    /// A stream of input values (global to the entire program).
    pub input_stream: Vec<u8>,

    /// A ptr to the current position in the input stream incremented by LWA opcode.
    pub input_stream_ptr: usize,

    /// A stream of output values from the program (global to entire program).
    pub output_stream: Vec<u8>,

    /// A ptr to the current position in the output stream, incremented when reading from output_stream.
    pub output_stream_ptr: usize,

    /// Segments
    pub segments: Vec<Segment>,

    /// The current segment for this section of the program.
    pub segment: Segment,

    /// The current record for the CPU event,
    pub record: Record,

    /// Global information needed for "global" chips, like the memory argument. It's a bit
    /// semantically incorrect to have this as a "Segment", since it's not really a segment
    /// in the traditional sense.
    pub global_segment: Segment,

    /// The maximum size of each segment.
    pub segment_size: u32,

    /// A counter for the number of cycles that have been executed in certain functions.
    pub cycle_tracker: HashMap<String, (u32, u32)>,

    /// A buffer for writing trace events to a file.
    pub trace_buf: Option<BufWriter<File>>,
}

impl Runtime {
    // Create a new runtime
    pub fn new(program: Program) -> Self {
        let program_rc = Arc::new(program);
        let segment = Segment {
            program: program_rc.clone(),
            index: 1,
            ..Default::default()
        };
        // Write trace to file if TRACE_FILE is set, write full if TRACE=full
        let trace_buf = if let Ok(trace_file) = std::env::var("TRACE_FILE") {
            let file = File::create(trace_file).unwrap();
            Some(BufWriter::new(file))
        } else {
            None
        };
        Self {
            global_clk: 0,
            clk: 0,
            pc: program_rc.pc_start,
            program: program_rc,
            memory: HashMap::with_hasher(BuildNoHashHasher::<u32>::default()),
            memory_access: HashMap::with_hasher(BuildNoHashHasher::<u32>::default()),
            input_stream: Vec::new(),
            input_stream_ptr: 0,
            output_stream: Vec::new(),
            output_stream_ptr: 0,
            segments: Vec::new(),
            segment,
            record: Record::default(),
            segment_size: 1048576,
            global_segment: Segment::default(),
            cycle_tracker: HashMap::new(),
            trace_buf,
        }
    }

    /// Get the current values of the registers.
    pub fn registers(&self) -> [u32; 32] {
        let mut registers = [0; 32];
        for i in 0..32 {
            let addr = Register::from_u32(i as u32) as u32;
            registers[i] = match self.memory.get(&addr) {
                Some(value) => *value,
                None => 0,
            };
        }
        registers
    }

    /// Get the current value of a register.
    pub fn register(&self, register: Register) -> u32 {
        let addr = register as u32;
        match self.memory.get(&addr) {
            Some(value) => *value,
            None => 0,
        }
    }

    /// Get the current value of a word.
    pub fn word(&self, addr: u32) -> u32 {
        match self.memory.get(&addr) {
            Some(value) => *value,
            None => 0,
        }
    }

    pub fn byte(&self, addr: u32) -> u8 {
        let word = self.word(addr - addr % 4);
        (word >> ((addr % 4) * 8)) as u8
    }

    fn clk_from_position(&self, position: &AccessPosition) -> u32 {
        self.clk + *position as u32
    }

    pub fn current_segment(&self) -> u32 {
        self.segment.index
    }

    fn align(&self, addr: u32) -> u32 {
        addr - addr % 4
    }

    fn validate_memory_access(&self, addr: u32, position: AccessPosition) {
        if position == AccessPosition::Memory {
            assert_eq!(addr % 4, 0, "addr is not aligned");
            let _ = BabyBear::from_canonical_u32(addr);
            assert!(addr > 40); // Assert that the address is > the max register.
        } else {
            let _ = Register::from_u32(addr);
        }
    }

    pub fn mr_core(&mut self, addr: u32, segment: u32, clk: u32) -> MemoryReadRecord {
        let value = *self.memory.entry(addr).or_insert(0);
        let (prev_segment, prev_timestamp) =
            self.memory_access.get(&addr).cloned().unwrap_or((0, 0));

        self.memory_access.insert(addr, (segment, clk));

        MemoryReadRecord::new(value, segment, clk, prev_segment, prev_timestamp)
    }

    pub fn mw_core(&mut self, addr: u32, value: u32, segment: u32, clk: u32) -> MemoryWriteRecord {
        let prev_value = *self.memory.entry(addr).or_insert(0);
        let (prev_segment, prev_timestamp) =
            self.memory_access.get(&addr).cloned().unwrap_or((0, 0));
        self.memory_access.insert(addr, (segment, clk));
        self.memory.insert(addr, value);
        MemoryWriteRecord::new(
            value,
            segment,
            clk,
            prev_value,
            prev_segment,
            prev_timestamp,
        )
    }

    /// Read from memory, assuming that all addresses are aligned.
    pub fn mr(&mut self, addr: u32, position: AccessPosition) -> u32 {
        self.validate_memory_access(addr, position);

        let record = self.mr_core(
            addr,
            self.current_segment(),
            self.clk_from_position(&position),
        );

        match position {
            AccessPosition::A => self.record.a = Some(record.into()),
            AccessPosition::B => self.record.b = Some(record.into()),
            AccessPosition::C => self.record.c = Some(record.into()),
            AccessPosition::Memory => self.record.memory = Some(record.into()),
        }
        record.value
    }

    /// Write to memory.
    pub fn mw(&mut self, addr: u32, value: u32, position: AccessPosition) {
        self.validate_memory_access(addr, position);

        let record = self.mw_core(
            addr,
            value,
            self.current_segment(),
            self.clk_from_position(&position),
        );

        // Set the records.
        match position {
            AccessPosition::A => {
                assert!(self.record.a.is_none());
                self.record.a = Some(record.into());
            }
            AccessPosition::B => {
                assert!(self.record.b.is_none());
                self.record.b = Some(record.into());
            }
            AccessPosition::C => {
                assert!(self.record.c.is_none());
                self.record.c = Some(record.into());
            }
            AccessPosition::Memory => {
                assert!(self.record.memory.is_none());
                self.record.memory = Some(record.into());
            }
        }
    }

    /// Read from register.
    pub fn rr(&mut self, register: Register, position: AccessPosition) -> u32 {
        self.mr(register as u32, position)
    }

    /// Write to register.
    pub fn rw(&mut self, register: Register, value: u32) {
        if register == Register::X0 {
            // We don't write to %x0. See 2.6 Load and Store Instruction on
            // P.18 of the RISC-V spec.
            return;
        }
        // The only time we are writing to a register is when it is register A.
        self.mw(register as u32, value, AccessPosition::A)
    }

    /// Emit a CPU event.
    #[allow(clippy::too_many_arguments)]
    fn emit_cpu(
        &mut self,
        segment: u32,
        clk: u32,
        pc: u32,
        instruction: Instruction,
        a: u32,
        b: u32,
        c: u32,
        memory_store_value: Option<u32>,
        record: Record,
    ) {
        let cpu_event = CpuEvent {
            segment,
            clk,
            pc,
            instruction,
            a,
            a_record: record.a,
            b,
            b_record: record.b,
            c,
            c_record: record.c,
            memory: memory_store_value,
            memory_record: record.memory,
        };
        self.segment.cpu_events.push(cpu_event);
    }

    /// Emit an ALU event.
    fn emit_alu(&mut self, clk: u32, opcode: Opcode, a: u32, b: u32, c: u32) {
        let event = AluEvent {
            clk,
            opcode,
            a,
            b,
            c,
        };
        match opcode {
            Opcode::ADD => {
                self.segment.add_events.push(event);
            }
            Opcode::SUB => {
                self.segment.sub_events.push(event);
            }
            Opcode::XOR | Opcode::OR | Opcode::AND => {
                self.segment.bitwise_events.push(event);
            }
            Opcode::SLL => {
                self.segment.shift_left_events.push(event);
            }
            Opcode::SRL | Opcode::SRA => {
                self.segment.shift_right_events.push(event);
            }
            Opcode::SLT | Opcode::SLTU => {
                self.segment.lt_events.push(event);
            }
            Opcode::MUL | Opcode::MULHU | Opcode::MULHSU | Opcode::MULH => {
                self.segment.mul_events.push(event);
            }
            Opcode::DIVU | Opcode::REMU | Opcode::DIV | Opcode::REM => {
                self.segment.divrem_events.push(event);
            }
            _ => {}
        }
    }

    /// Fetch the destination register and input operand values for an ALU instruction.
    #[inline]
    fn alu_rr(&mut self, instruction: Instruction) -> (Register, u32, u32) {
        if !instruction.imm_c {
            let (rd, rs1, rs2) = instruction.r_type();
            let c = self.rr(rs2, AccessPosition::C);
            let b = self.rr(rs1, AccessPosition::B);
            (rd, b, c)
        } else if !instruction.imm_b && instruction.imm_c {
            let (rd, rs1, imm) = instruction.i_type();
            let (rd, b, c) = (rd, self.rr(rs1, AccessPosition::B), imm);
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
    #[inline]
    fn alu_rw(&mut self, instruction: Instruction, rd: Register, a: u32, b: u32, c: u32) {
        self.rw(rd, a);
        self.emit_alu(self.clk, instruction.opcode, a, b, c);
    }

    /// Fetch the input operand values for a load instruction.
    #[inline]
    fn load_rr(&mut self, instruction: Instruction) -> (Register, u32, u32, u32, u32) {
        let (rd, rs1, imm) = instruction.i_type();
        let (b, c) = (self.rr(rs1, AccessPosition::B), imm);
        let addr = b.wrapping_add(c);
        let memory_value = self.mr(self.align(addr), AccessPosition::Memory);
        (rd, b, c, addr, memory_value)
    }

    /// Fetch the input operand values for a store instruction.
    #[inline]
    fn store_rr(&mut self, instruction: Instruction) -> (u32, u32, u32, u32, u32) {
        let (rs1, rs2, imm) = instruction.s_type();
        let c = imm;
        let b = self.rr(rs2, AccessPosition::B);
        let a = self.rr(rs1, AccessPosition::A);
        let addr = b.wrapping_add(c);
        let memory_value = self.word(self.align(addr));
        (a, b, c, addr, memory_value)
    }

    /// Fetch the input operand values for a branch instruction.
    #[inline]
    fn branch_rr(&mut self, instruction: Instruction) -> (u32, u32, u32) {
        let (rs1, rs2, imm) = instruction.b_type();
        let c = imm;
        let b = self.rr(rs2, AccessPosition::B);
        let a = self.rr(rs1, AccessPosition::A);
        (a, b, c)
    }

    /// Fetch the instruction at the current program counter.
    fn fetch(&self) -> Instruction {
        let idx = ((self.pc - self.program.pc_base) / 4) as usize;
        self.program.instructions[idx]
    }

    /// Execute the given instruction over the current state of the runtime.
    fn execute(&mut self, instruction: Instruction) {
        let pc = self.pc;
        let mut next_pc = self.pc.wrapping_add(4);

        let rd: Register;
        let (a, b, c): (u32, u32, u32);
        let (addr, memory_read_value): (u32, u32);
        let mut memory_store_value: Option<u32> = None;
        self.record = Record::default();

        match instruction.opcode {
            // Arithmetic instructions.
            Opcode::ADD => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_add(c);
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::SUB => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_sub(c);
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::XOR => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b ^ c;
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::OR => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b | c;
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::AND => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b & c;
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::SLL => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_shl(c);
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::SRL => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_shr(c);
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::SRA => {
                (rd, b, c) = self.alu_rr(instruction);
                a = (b as i32).wrapping_shr(c) as u32;
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::SLT => {
                (rd, b, c) = self.alu_rr(instruction);
                a = if (b as i32) < (c as i32) { 1 } else { 0 };
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::SLTU => {
                (rd, b, c) = self.alu_rr(instruction);
                a = if b < c { 1 } else { 0 };
                self.alu_rw(instruction, rd, a, b, c);
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
                assert_eq!(addr % 2, 0, "addr is not aligned");
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
                assert_eq!(addr % 4, 0, "addr is not aligned");
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
                assert_eq!(addr % 2, 0, "addr is not aligned");
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
                self.mw(self.align(addr), value, AccessPosition::Memory);
            }
            Opcode::SH => {
                (a, b, c, addr, memory_read_value) = self.store_rr(instruction);
                assert_eq!(addr % 2, 0, "addr is not aligned");
                let value = match (addr >> 1) % 2 {
                    0 => (a & 0x0000FFFF) + (memory_read_value & 0xFFFF0000),
                    1 => ((a & 0x0000FFFF) << 16) + (memory_read_value & 0x0000FFFF),
                    _ => unreachable!(),
                };
                memory_store_value = Some(value);
                self.mw(self.align(addr), value, AccessPosition::Memory);
            }
            Opcode::SW => {
                (a, b, c, addr, _) = self.store_rr(instruction);
                assert_eq!(addr % 4, 0, "addr is not aligned");
                let value = a;
                memory_store_value = Some(value);
                self.mw(self.align(addr), value, AccessPosition::Memory);
            }

            // B-type instructions.
            Opcode::BEQ => {
                (a, b, c) = self.branch_rr(instruction);
                if a == b {
                    next_pc = self.pc.wrapping_add(c);
                }
            }
            Opcode::BNE => {
                (a, b, c) = self.branch_rr(instruction);
                if a != b {
                    next_pc = self.pc.wrapping_add(c);
                }
            }
            Opcode::BLT => {
                (a, b, c) = self.branch_rr(instruction);
                if (a as i32) < (b as i32) {
                    next_pc = self.pc.wrapping_add(c);
                }
            }
            Opcode::BGE => {
                (a, b, c) = self.branch_rr(instruction);
                if (a as i32) >= (b as i32) {
                    next_pc = self.pc.wrapping_add(c);
                }
            }
            Opcode::BLTU => {
                (a, b, c) = self.branch_rr(instruction);
                if a < b {
                    next_pc = self.pc.wrapping_add(c);
                }
            }
            Opcode::BGEU => {
                (a, b, c) = self.branch_rr(instruction);
                if a >= b {
                    next_pc = self.pc.wrapping_add(c);
                }
            }

            // Jump instructions.
            Opcode::JAL => {
                let (rd, imm) = instruction.j_type();
                (b, c) = (imm, 0);
                a = self.pc + 4;
                self.rw(rd, a);
                next_pc = self.pc.wrapping_add(imm);
            }
            Opcode::JALR => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1, AccessPosition::B), imm);
                a = self.pc + 4;
                self.rw(rd, a);
                next_pc = b.wrapping_add(c);
            }

            // Upper immediate instructions.
            Opcode::AUIPC => {
                let (rd, imm) = instruction.u_type();
                (b, c) = (imm, imm);
                a = self.pc.wrapping_add(b);
                self.rw(rd, a);
            }

            // System instructions.
            Opcode::ECALL => {
                let t0 = Register::X5;
                let a0 = Register::X10;
                let a1 = Register::X11;
                let a2 = Register::X12;
                let syscall_id = self.register(t0);
                let syscall = Syscall::from_u32(syscall_id);

                let init_clk = self.clk;
                let mut precompile_rt = PrecompileRuntime::new(self);

                match syscall {
                    Syscall::HALT => {
                        a = self.register(a0);
                        next_pc = 0;
                    }
                    Syscall::LWA => {
                        // TODO: in the future this will be used for private vs. public inputs.
                        let _ = self.register(a0);
                        let num_bytes = self.register(a1) as usize;
                        let mut read_bytes = [0u8; 4];
                        for i in 0..num_bytes {
                            if self.input_stream_ptr >= self.input_stream.len() {
                                tracing::error!("Not enough input words were passed in. Use --input to pass in more words.");
                                exit(1);
                            }
                            read_bytes[i] = self.input_stream[self.input_stream_ptr];
                            self.input_stream_ptr += 1;
                        }
                        let word = u32::from_le_bytes(read_bytes);
                        a = word;
                    }
                    Syscall::SHA_EXTEND => {
                        a = ShaExtendChip::execute(&mut precompile_rt);
                        self.clk = precompile_rt.clk;
                        assert_eq!(init_clk + ShaExtendChip::NUM_CYCLES, self.clk);
                    }
                    Syscall::SHA_COMPRESS => {
                        a = ShaCompressChip::execute(&mut precompile_rt);
                        self.clk = precompile_rt.clk;
                        assert_eq!(init_clk + ShaCompressChip::NUM_CYCLES, self.clk);
                    }
                    Syscall::KECCAK_PERMUTE => {
                        a = KeccakPermuteChip::execute(&mut precompile_rt);
                        self.clk = precompile_rt.clk;
                        assert_eq!(init_clk + KeccakPermuteChip::NUM_CYCLES, self.clk);
                    }
                    Syscall::WRITE => {
                        let fd = self.register(a0);
                        if fd == 1 || fd == 2 || fd == 3 {
                            let write_buf = self.register(a1);
                            let nbytes = self.register(a2);
                            // Read nbytes from memory starting at write_buf.
                            let bytes = (0..nbytes)
                                .map(|i| self.byte(write_buf + i))
                                .collect::<Vec<u8>>();
                            let slice = bytes.as_slice();
                            if fd == 1 {
                                let s = core::str::from_utf8(slice).unwrap();
                                if s.contains("cycle-tracker-start:") {
                                    let fn_name = s
                                        .split("cycle-tracker-start:")
                                        .last()
                                        .unwrap()
                                        .trim_end()
                                        .trim_start();
                                    let depth = self.cycle_tracker.len() as u32;
                                    self.cycle_tracker
                                        .insert(fn_name.to_string(), (self.global_clk, depth));
                                    let padding = (0..depth).map(|_| "│ ").collect::<String>();
                                    log::info!("{}┌╴{}", padding, fn_name);
                                } else if s.contains("cycle-tracker-end:") {
                                    let fn_name = s
                                        .split("cycle-tracker-end:")
                                        .last()
                                        .unwrap()
                                        .trim_end()
                                        .trim_start();
                                    let (start, depth) =
                                        self.cycle_tracker.remove(fn_name).unwrap_or((0, 0));
                                    // Leftpad by 2 spaces for each depth.
                                    let padding = (0..depth).map(|_| "│ ").collect::<String>();
                                    log::info!(
                                        "{}└╴{} cycles",
                                        padding,
                                        u32_to_comma_separated(self.global_clk - start)
                                    );
                                } else {
                                    log::info!("stdout: {}", s.trim_end());
                                }
                            } else if fd == 2 {
                                let s = core::str::from_utf8(slice).unwrap();
                                log::info!("stderr: {}", s.trim_end());
                            } else if fd == 3 {
                                self.output_stream.extend_from_slice(slice);
                            } else {
                                unreachable!()
                            }
                        }
                        a = 0;
                    }
                    Syscall::ED_ADD => {
                        a = EdAddAssignChip::<EdwardsCurve<Ed25519Parameters>, Ed25519Parameters>::execute(
                            &mut precompile_rt,
                        );
                        self.clk = precompile_rt.clk;
                        assert_eq!(
                            init_clk
                                + EdAddAssignChip::<
                                    EdwardsCurve<Ed25519Parameters>,
                                    Ed25519Parameters,
                                >::NUM_CYCLES,
                            self.clk
                        );
                    }
                    Syscall::ED_DECOMPRESS => {
                        a = EdDecompressChip::<Ed25519Parameters>::execute(&mut precompile_rt);
                        self.clk = precompile_rt.clk;
                        assert_eq!(init_clk + 4, self.clk);
                    }
                    Syscall::SECP256K1_ADD => {
                        a = WeierstrassAddAssignChip::<
                            SWCurve<Secp256k1Parameters>,
                            Secp256k1Parameters,
                        >::execute(&mut precompile_rt);
                        self.clk = precompile_rt.clk;
                        assert_eq!(
                            init_clk
                                + WeierstrassAddAssignChip::<
                                    SWCurve<Secp256k1Parameters>,
                                    Secp256k1Parameters,
                                >::NUM_CYCLES,
                            self.clk
                        );
                    }
                    Syscall::SECP256K1_DOUBLE => {
                        a = WeierstrassDoubleAssignChip::<
                            SWCurve<Secp256k1Parameters>,
                            Secp256k1Parameters,
                        >::execute(&mut precompile_rt);
                        self.clk = precompile_rt.clk;
                        assert_eq!(
                            init_clk
                                + WeierstrassDoubleAssignChip::<
                                    SWCurve<Secp256k1Parameters>,
                                    Secp256k1Parameters,
                                >::NUM_CYCLES,
                            self.clk
                        );
                    }
                    Syscall::SECP256K1_DECOMPRESS => {
                        a = K256DecompressChip::execute(&mut precompile_rt);
                        self.clk = precompile_rt.clk;
                        assert_eq!(init_clk + 4, self.clk);
                    }
                }

                // We have to do this AFTER the precompile execution because the CPU event
                // gets emitted at the end of this loop with the incremented clock.
                // TODO: fix this.
                self.rw(a0, a);
                (b, c) = (self.rr(t0, AccessPosition::B), 0);
            }

            Opcode::EBREAK => {
                todo!()
            }

            // Multiply instructions.
            Opcode::MUL => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_mul(c);
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::MULH => {
                (rd, b, c) = self.alu_rr(instruction);
                a = (((b as i32) as i64).wrapping_mul((c as i32) as i64) >> 32) as u32;
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::MULHU => {
                (rd, b, c) = self.alu_rr(instruction);
                a = ((b as u64).wrapping_mul(c as u64) >> 32) as u32;
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::MULHSU => {
                (rd, b, c) = self.alu_rr(instruction);
                a = (((b as i32) as i64).wrapping_mul(c as i64) >> 32) as u32;
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::DIV => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = u32::MAX;
                } else {
                    a = (b as i32).wrapping_div(c as i32) as u32;
                }
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::DIVU => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = u32::MAX;
                } else {
                    a = b.wrapping_div(c);
                }
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::REM => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = b;
                } else {
                    a = (b as i32).wrapping_rem(c as i32) as u32;
                }
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::REMU => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = b;
                } else {
                    a = b.wrapping_rem(c);
                }
                self.alu_rw(instruction, rd, a, b, c);
            }

            Opcode::UNIMP => {
                // See https://github.com/riscv-non-isa/riscv-asm-manual/blob/master/riscv-asm.md#instruction-aliases
                panic!("UNIMP encountered, we should never get here.");
            }
        }

        // Update the program counter.
        self.pc = next_pc;

        // Emit the CPU event for this cycle.
        self.emit_cpu(
            self.current_segment(),
            self.clk,
            pc,
            instruction,
            a,
            b,
            c,
            memory_store_value,
            self.record,
        );
    }

    /// Execute the program.
    pub fn run(&mut self) {
        // First load the memory image into the memory table.
        for (addr, value) in self.program.memory_image.iter() {
            self.memory.insert(*addr, *value);
            self.memory_access.insert(*addr, (0, 0));
        }

        self.clk += 1;
        while self.pc.wrapping_sub(self.program.pc_base)
            < (self.program.instructions.len() * 4) as u32
        {
            // Fetch the instruction at the current program counter.
            let instruction = self.fetch();

            if self.global_clk % 1000000000 == 0 {
                log::info!("global_clk={}", self.global_clk);
            }

            let width = 12;
            if let Some(ref mut buf) = self.trace_buf {
                writeln!(buf, "{:x?}", self.pc).unwrap();
            }

            log::trace!(
                "clk={} [pc=0x{:x?}] {:<width$?} |         x0={:<width$} x1={:<width$} x2={:<width$} x3={:<width$} x4={:<width$} x5={:<width$} x6={:<width$} x7={:<width$} x8={:<width$} x9={:<width$} x10={:<width$} x11={:<width$} x12={:<width$} x13={:<width$} x14={:<width$} x15={:<width$} x16={:<width$} x17={:<width$} x18={:<width$}",
                self.global_clk,
                self.pc,
                instruction,
                self.register(Register::X0),
                self.register(Register::X1),
                self.register(Register::X2),
                self.register(Register::X3),
                self.register(Register::X4),
                self.register(Register::X5),
                self.register(Register::X6),
                self.register(Register::X7),
                self.register(Register::X8),
                self.register(Register::X9),
                self.register(Register::X10),
                self.register(Register::X11),
                self.register(Register::X12),
                self.register(Register::X13),
                self.register(Register::X14),
                self.register(Register::X15),
                self.register(Register::X16),
                self.register(Register::X17),
                self.register(Register::X18),
            );

            // Execute the instruction.
            self.execute(instruction);

            // Increment the clock.
            self.global_clk += 1;
            self.clk += 4;

            if self.clk % self.segment_size == 1 {
                let segment = std::mem::take(&mut self.segment);
                self.segments.push(segment);
                // Set up new segment
                self.segment.index = self.segments.len() as u32 + 1;
                self.segment.program = self.program.clone();
                self.clk = 1;
            }
        }
        if let Some(ref mut buf) = self.trace_buf {
            buf.flush().unwrap();
        }

        // Push the last segment.
        if !self.segment.cpu_events.is_empty() {
            self.segments.push(self.segment.clone());
        }

        // Call postprocess to set up all variables needed for global accounts, like memory
        // argument or any other deferred tables.
        self.postprocess();
    }

    fn postprocess(&mut self) {
        let mut program_memory_used = HashMap::with_hasher(BuildNoHashHasher::<u32>::default());
        for (key, value) in &self.program.memory_image {
            // By default we assume that the program_memory is used.
            program_memory_used.insert(*key, (*value, 1));
        }

        let mut first_memory_record = Vec::new();
        let mut last_memory_record = Vec::new();

        let memory_keys = self.memory.keys().cloned().collect::<Vec<u32>>();
        for addr in memory_keys {
            let value = *self.memory.get(&addr).unwrap();
            let (segment, timestamp) = *self.memory_access.get(&addr).unwrap();
            if segment == 0 && timestamp == 0 {
                // This means that we never accessed this memory location throughout our entire program.
                // The only way this can happen is if this was in the program memory image.
                // We mark this (addr, value) as not used in the `program_memory_used` map.
                program_memory_used.insert(addr, (value, 0));
                continue;
            }
            // If the memory addr was accessed, we only add it to "first_memory_record" if it was
            // not in the program_memory_image, otherwise we'll add to the memory argument from
            // the program_memory_image table.
            if !self.program.memory_image.contains_key(&addr) {
                first_memory_record.push((
                    addr,
                    MemoryRecord {
                        value: 0,
                        segment: 0,
                        timestamp: 0,
                    },
                    1,
                ));
            }

            last_memory_record.push((
                addr,
                MemoryRecord {
                    value,
                    segment,
                    timestamp,
                },
                1,
            ));
        }

        let mut program_memory_record = program_memory_used
            .iter()
            .map(|(&addr, &(value, used))| {
                (
                    addr,
                    MemoryRecord {
                        value,
                        segment: 0,
                        timestamp: 0,
                    },
                    used,
                )
            })
            .collect::<Vec<(u32, MemoryRecord, u32)>>();
        program_memory_record.sort_by_key(|&(addr, _, _)| addr);

        self.global_segment.first_memory_record = first_memory_record;
        self.global_segment.last_memory_record = last_memory_record;
        self.global_segment.program_memory_record = program_memory_record;
    }
}

#[cfg(test)]
pub mod tests {

    use crate::{runtime::Register, utils::tests::FIBONACCI_ELF};

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

    pub fn ecall_lwa_program() -> Program {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 5, 0, 101, false, true),
            Instruction::new(Opcode::ECALL, 10, 5, 0, false, true),
        ];
        Program::new(instructions, 0, 0)
    }

    #[test]
    fn test_simple_program_run() {
        let program = simple_program();
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.register(Register::X31), 42);
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
        let mut runtime = Runtime::new(program);
        runtime.run();
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

        let mut runtime = Runtime::new(program);
        runtime.run();
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

        let mut runtime = Runtime::new(program);
        runtime.run();
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

        let mut runtime = Runtime::new(program);

        runtime.run();
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

        let mut runtime = Runtime::new(program);
        runtime.run();
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

        let mut runtime = Runtime::new(program);
        runtime.run();
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

        let mut runtime = Runtime::new(program);
        runtime.run();
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

        let mut runtime = Runtime::new(program);
        runtime.run();
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

        let mut runtime = Runtime::new(program);
        runtime.run();
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

        let mut runtime = Runtime::new(program);
        runtime.run();
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

        let mut runtime = Runtime::new(program);
        runtime.run();
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
        let mut runtime = Runtime::new(program);
        runtime.run();
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
        let mut runtime = Runtime::new(program);
        runtime.run();
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
        let mut runtime = Runtime::new(program);
        runtime.run();
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
        let mut runtime = Runtime::new(program);
        runtime.run();
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
        let mut runtime = Runtime::new(program);
        runtime.run();
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
        let mut runtime = Runtime::new(program);
        runtime.run();
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
        let mut runtime = Runtime::new(program);
        runtime.run();
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
        let mut runtime = Runtime::new(program);
        runtime.run();
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
        let mut runtime = Runtime::new(program);
        runtime.run();
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
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X5 as usize], 8);
        assert_eq!(runtime.registers()[Register::X11 as usize], 100);
        assert_eq!(runtime.pc, 108);
    }

    fn simple_op_code_test(opcode: Opcode, expected: u32, a: u32, b: u32) {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 10, 0, a, false, true),
            Instruction::new(Opcode::ADD, 11, 0, b, false, true),
            Instruction::new(opcode, 12, 10, 11, false, false),
        ];
        let program = Program::new(instructions, 0, 0);
        let mut runtime = Runtime::new(program);
        runtime.run();
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
        let mut runtime = Runtime::new(program);
        runtime.run();

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
