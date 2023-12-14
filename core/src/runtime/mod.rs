//! An implementation of a runtime for the Curta VM.
//!
//! The runtime is responsible for executing a user program and tracing important events which occur
//! during execution (i.e., memory reads, alu operations, etc).
//!
//! For more information on the RV32IM instruction set, see the following:
//! https://www.cs.sfu.ca/~ashriram/Courses/CS295/assets/notebooks/RISCV/RISCV_CARD.pdf

use std::{
    collections::BTreeMap,
    fmt::{Display, Formatter},
};

use crate::prover::{debug_constraints, debug_cumulative_sums, generate_permutation_trace};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{Pcs, UnivariatePcs};
use p3_field::{ExtensionField, PrimeField, TwoAdicField};
use p3_matrix::Matrix;
use p3_uni_stark::StarkConfig;
use p3_util::log2_strict_usize;

use crate::{
    alu::{add::AddChip, bitwise::BitwiseChip, sub::SubChip, AluEvent},
    cpu::{trace::CpuChip, CpuEvent},
    memory::{MemOp, MemoryEvent},
    program::ProgramChip,
    utils::Chip,
};

/// An opcode specifies which operation to execute.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
pub enum Opcode {
    /// Register instructions.
    ADD = 0,
    SUB = 1,
    XOR = 2,
    OR = 3,
    AND = 4,
    SLL = 5,
    SRL = 6,
    SRA = 7,
    SLT = 8,
    SLTU = 9,

    /// Immediate instructions.
    ADDI = 10,
    XORI = 11,
    ORI = 12,
    ANDI = 13,
    SLLI = 14,
    SRLI = 15,
    SRAI = 16,
    SLTI = 17,
    SLTIU = 18,

    /// Load instructions.
    LB = 19,
    LH = 20,
    LW = 21,
    LBU = 22,
    LHU = 23,

    /// Store instructions.
    SB = 24,
    SH = 25,
    SW = 26,

    /// Branch instructions.
    BEQ = 27,
    BNE = 28,
    BLT = 29,
    BGE = 30,
    BLTU = 31,
    BGEU = 32,

    /// Jump instructions.
    JAL = 33,
    JALR = 34,
    LUI = 35,
    AUIPC = 36,

    /// System instructions.
    ECALL = 37,
    EBREAK = 38,

    /// Multiply instructions.
    MUL = 39,
    MULH = 40,
    MULSU = 41,
    MULU = 42,
    DIV = 43,
    DIVU = 44,
    REM = 45,
    REMU = 46,
}

impl Display for Opcode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            // R-type instructions.
            Opcode::ADD => write!(f, "add"),
            Opcode::SUB => write!(f, "sub"),
            Opcode::XOR => write!(f, "xor"),
            Opcode::OR => write!(f, "or"),
            Opcode::AND => write!(f, "and"),
            Opcode::SLL => write!(f, "sll"),
            Opcode::SRL => write!(f, "srl"),
            Opcode::SRA => write!(f, "sra"),
            Opcode::SLT => write!(f, "slt"),
            Opcode::SLTU => write!(f, "sltu"),

            // I-type instructions.
            Opcode::ADDI => write!(f, "addi"),
            Opcode::XORI => write!(f, "xori"),
            Opcode::ORI => write!(f, "ori"),
            Opcode::ANDI => write!(f, "andi"),
            Opcode::SLLI => write!(f, "slli"),
            Opcode::SRLI => write!(f, "srli"),
            Opcode::SRAI => write!(f, "srai"),
            Opcode::SLTI => write!(f, "slti"),
            Opcode::SLTIU => write!(f, "sltiu"),

            // Load instructions.
            Opcode::LB => write!(f, "lb"),
            Opcode::LH => write!(f, "lh"),
            Opcode::LW => write!(f, "lw"),
            Opcode::LBU => write!(f, "lbu"),
            Opcode::LHU => write!(f, "lhu"),

            // Store instructions.
            Opcode::SB => write!(f, "sb"),
            Opcode::SH => write!(f, "sh"),
            Opcode::SW => write!(f, "sw"),

            // Branch instructions.
            Opcode::BEQ => write!(f, "beq"),
            Opcode::BNE => write!(f, "bne"),
            Opcode::BLT => write!(f, "blt"),
            Opcode::BGE => write!(f, "bge"),
            Opcode::BLTU => write!(f, "bltu"),
            Opcode::BGEU => write!(f, "bgeu"),

            // Jump instructions.
            Opcode::JAL => write!(f, "jal"),
            Opcode::JALR => write!(f, "jalr"),

            // Upper immediate instructions.
            Opcode::LUI => write!(f, "lui"),
            Opcode::AUIPC => write!(f, "auipc"),

            // System instructions.
            Opcode::ECALL => write!(f, "ecall"),
            Opcode::EBREAK => write!(f, "ebreak"),

            // Multiply instructions.
            Opcode::MUL => write!(f, "mul"),
            Opcode::MULH => write!(f, "mulh"),
            Opcode::MULSU => write!(f, "mulsu"),
            Opcode::MULU => write!(f, "mulu"),
            Opcode::DIV => write!(f, "div"),
            Opcode::DIVU => write!(f, "divu"),
            Opcode::REM => write!(f, "rem"),
            Opcode::REMU => write!(f, "remu"),
        }
    }
}

/// A register stores a 32-bit value used by operations.
#[derive(Debug, Clone, Copy)]
pub enum Register {
    X0 = 0,
    X1 = 1,
    X2 = 2,
    X3 = 3,
    X4 = 4,
    X5 = 5,
    X6 = 6,
    X7 = 7,
    X8 = 8,
    X9 = 9,
    X10 = 10,
    X11 = 11,
    X12 = 12,
    X13 = 13,
    X14 = 14,
    X15 = 15,
    X16 = 16,
    X17 = 17,
    X18 = 18,
    X19 = 19,
    X20 = 20,
    X21 = 21,
    X22 = 22,
    X23 = 23,
    X24 = 24,
    X25 = 25,
    X26 = 26,
    X27 = 27,
    X28 = 28,
    X29 = 29,
    X30 = 30,
    X31 = 31,
}

impl Register {
    fn from_u32(value: u32) -> Self {
        match value {
            0 => Register::X0,
            1 => Register::X1,
            2 => Register::X2,
            3 => Register::X3,
            4 => Register::X4,
            5 => Register::X5,
            6 => Register::X6,
            7 => Register::X7,
            8 => Register::X8,
            9 => Register::X9,
            10 => Register::X10,
            11 => Register::X11,
            12 => Register::X12,
            13 => Register::X13,
            14 => Register::X14,
            15 => Register::X15,
            16 => Register::X16,
            17 => Register::X17,
            18 => Register::X18,
            19 => Register::X19,
            20 => Register::X20,
            21 => Register::X21,
            22 => Register::X22,
            23 => Register::X23,
            24 => Register::X24,
            25 => Register::X25,
            26 => Register::X26,
            27 => Register::X27,
            28 => Register::X28,
            29 => Register::X29,
            30 => Register::X30,
            31 => Register::X31,
            _ => panic!("Invalid register"),
        }
    }
}

impl Display for Register {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Register::X0 => write!(f, "%x0"),
            Register::X1 => write!(f, "%x1"),
            Register::X2 => write!(f, "%x2"),
            Register::X3 => write!(f, "%x3"),
            Register::X4 => write!(f, "%x4"),
            Register::X5 => write!(f, "%x5"),
            Register::X6 => write!(f, "%x6"),
            Register::X7 => write!(f, "%x7"),
            Register::X8 => write!(f, "%x8"),
            Register::X9 => write!(f, "%x9"),
            Register::X10 => write!(f, "%x10"),
            Register::X11 => write!(f, "%x11"),
            Register::X12 => write!(f, "%x12"),
            Register::X13 => write!(f, "%x13"),
            Register::X14 => write!(f, "%x14"),
            Register::X15 => write!(f, "%x15"),
            Register::X16 => write!(f, "%x16"),
            Register::X17 => write!(f, "%x17"),
            Register::X18 => write!(f, "%x18"),
            Register::X19 => write!(f, "%x19"),
            Register::X20 => write!(f, "%x20"),
            Register::X21 => write!(f, "%x21"),
            Register::X22 => write!(f, "%x22"),
            Register::X23 => write!(f, "%x23"),
            Register::X24 => write!(f, "%x24"),
            Register::X25 => write!(f, "%x25"),
            Register::X26 => write!(f, "%x26"),
            Register::X27 => write!(f, "%x27"),
            Register::X28 => write!(f, "%x28"),
            Register::X29 => write!(f, "%x29"),
            Register::X30 => write!(f, "%x30"),
            Register::X31 => write!(f, "%x31"),
        }
    }
}

/// An instruction specifies an operation to execute and the operands.
#[derive(Debug, Clone, Copy)]
pub struct Instruction {
    pub opcode: Opcode,
    pub op_a: u32,
    pub op_b: u32,
    pub op_c: u32,
}

impl Instruction {
    /// Create a new instruction.
    pub fn new(opcode: Opcode, op_a: u32, op_b: u32, op_c: u32) -> Instruction {
        Instruction {
            opcode,
            op_a,
            op_b,
            op_c,
        }
    }

    /// Decode the instruction in the R-type format.
    pub fn r_type(&self) -> (Register, Register, Register) {
        (
            Register::from_u32(self.op_a),
            Register::from_u32(self.op_b),
            Register::from_u32(self.op_c),
        )
    }

    /// Decode the instruction in the I-type format.
    pub fn i_type(&self) -> (Register, Register, u32) {
        (
            Register::from_u32(self.op_a),
            Register::from_u32(self.op_b),
            self.op_c,
        )
    }

    /// Decode the instruction in the S-type format.
    pub fn s_type(&self) -> (Register, Register, u32) {
        (
            Register::from_u32(self.op_a),
            Register::from_u32(self.op_b),
            self.op_c,
        )
    }

    /// Decode the instruction in the B-type format.
    pub fn b_type(&self) -> (Register, Register, u32) {
        (
            Register::from_u32(self.op_a),
            Register::from_u32(self.op_b),
            self.op_c,
        )
    }

    /// Decode the instruction in the J-type format.
    pub fn j_type(&self) -> (Register, u32) {
        (Register::from_u32(self.op_a), self.op_b)
    }

    /// Decode the instruction in the U-type format.
    pub fn u_type(&self) -> (Register, u32) {
        (Register::from_u32(self.op_a), self.op_b)
    }
}

/// A runtime executes a program.
#[derive(Debug)]
pub struct Runtime {
    /// The clock keeps track of how many instructions have been executed.
    pub clk: u32,

    /// The program counter keeps track of the next instruction.
    pub pc: u32,

    /// The prgram used during execution.
    pub program: Vec<Instruction>,

    /// The memory which instructions operate over.
    pub memory: BTreeMap<u32, u32>,

    /// A trace of the CPU events which get emitted during execution.
    pub cpu_events: Vec<CpuEvent>,

    /// A trace of the memory events which get emitted during execution.
    pub memory_events: Vec<MemoryEvent>,

    /// A trace of the ADD, and ADDI events.
    pub add_events: Vec<AluEvent>,

    /// A trace of the SUB events.
    pub sub_events: Vec<AluEvent>,

    /// A trace of the XOR, XORI, OR, ORI, AND, and ANDI events.
    pub bitwise_events: Vec<AluEvent>,
}

impl Runtime {
    /// Create a new runtime.
    pub fn new(program: Vec<Instruction>) -> Self {
        Self {
            clk: 0,
            pc: 0,
            memory: BTreeMap::new(),
            program,
            cpu_events: Vec::new(),
            memory_events: Vec::new(),
            add_events: Vec::new(),
            sub_events: Vec::new(),
            bitwise_events: Vec::new(),
        }
    }

    /// Read from memory.
    fn mr(&mut self, addr: u32) -> u32 {
        let value = match self.memory.get(&addr) {
            Some(value) => *value,
            None => 0,
        };
        self.emit_memory(self.clk, addr, MemOp::Read, value);
        return value;
    }

    /// Write to memory.
    fn mw(&mut self, addr: u32, value: u32) {
        self.memory.insert(addr, value);
        self.emit_memory(self.clk, addr, MemOp::Write, value);
    }

    /// Convert a register to a memory address.
    fn r2m(&self, register: Register) -> u32 {
        1024 * 1024 * 8 + (register as u32)
    }

    /// Read from register.
    fn rr(&mut self, register: Register) -> u32 {
        let addr = self.r2m(register);
        self.mr(addr)
    }

    /// Write to register.
    fn rw(&mut self, register: Register, value: u32) {
        let addr = self.r2m(register);
        self.mw(addr, value);
    }

    /// Get the current values of the registers.
    pub fn registers(&self) -> [u32; 32] {
        let mut registers = [0; 32];
        for i in 0..32 {
            let addr = self.r2m(Register::from_u32(i as u32));
            registers[i] = match self.memory.get(&addr) {
                Some(value) => *value,
                None => 0,
            };
        }
        return registers;
    }

    /// Fetch the instruction at the current program counter.
    fn fetch(&self) -> Instruction {
        let idx = (self.pc / 4) as usize;
        return self.program[idx];
    }

    /// Emit a CPU event.
    fn emit_cpu(&mut self, clk: u32, pc: u32, instruction: Instruction, a: u32, b: u32, c: u32) {
        self.cpu_events.push(CpuEvent {
            clk: clk,
            pc: pc,
            instruction,
            a,
            b,
            c,
        });
    }

    /// Emit a memory event.
    fn emit_memory(&mut self, clk: u32, addr: u32, op: MemOp, value: u32) {
        self.memory_events.push(MemoryEvent {
            clk,
            addr,
            op,
            value,
        });
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
            Opcode::ADD | Opcode::ADDI => {
                self.add_events.push(event);
            }
            Opcode::SUB => {
                self.sub_events.push(event);
            }
            Opcode::XOR | Opcode::XORI | Opcode::OR | Opcode::ORI | Opcode::AND | Opcode::ANDI => {
                self.bitwise_events.push(event);
            }
            _ => {}
        }
    }

    /// Execute the given instruction over the current state of the runtime.
    fn execute(&mut self, instruction: Instruction) {
        let pc = self.pc;
        let (mut a, mut b, mut c): (u32, u32, u32) = (u32::MAX, u32::MAX, u32::MAX);
        match instruction.opcode {
            // R-type instructions.
            Opcode::ADD => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = b.wrapping_add(c);
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SUB => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = b.wrapping_sub(c);
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::XOR => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = b ^ c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::OR => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = b | c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::AND => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = b & c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SLL => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = b << c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SRL => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = b >> c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SRA => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = (b as i32 >> c) as u32;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SLT => {
                let (rd, rs1, rs2) = instruction.r_type();
                (b, c) = (self.rr(rs1), self.rr(rs2));
                a = if (b as i32) < (c as i32) { 1 } else { 0 };
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SLTU => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = if b < c { 1 } else { 0 };
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }

            // I-type instructions.
            Opcode::ADDI => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = b.wrapping_add(c);
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::XORI => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = b ^ c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::ORI => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = b | c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::ANDI => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = b & c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SLLI => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = b << c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SRLI => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = b >> c;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SRAI => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = (b as i32 >> c) as u32;
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SLTI => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = if (b as i32) < (c as i32) { 1 } else { 0 };
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }
            Opcode::SLTIU => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = if b < c { 1 } else { 0 };
                self.rw(rd, a);
                self.emit_alu(self.clk, instruction.opcode, a, b, c);
            }

            // Load instructions
            Opcode::LB => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                let addr = b.wrapping_add(c);
                a = (self.mr(addr) as i8) as u32;
                self.rw(rd, a);
            }
            Opcode::LH => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                let addr = b.wrapping_add(c);
                a = (self.mr(addr) as i16) as u32;
                self.rw(rd, a);
            }
            Opcode::LW => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                let addr = b.wrapping_add(c);
                a = self.mr(addr);
                self.rw(rd, a);
            }
            Opcode::LBU => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                let addr = b.wrapping_add(c);
                let a = (self.mr(addr) as u8) as u32;
                self.rw(rd, a);
            }
            Opcode::LHU => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                let addr = b.wrapping_add(c);
                let a = (self.mr(addr) as u16) as u32;
                self.rw(rd, a);
            }

            // S-type instructions.
            Opcode::SB => {
                let (rs1, rs2, imm) = instruction.s_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                let addr = a.wrapping_add(c);
                let value = (b as u8) as u32;
                self.mw(addr, value);
            }
            Opcode::SH => {
                let (rs1, rs2, imm) = instruction.s_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                let addr = a.wrapping_add(c);
                let value = (b as u16) as u32;
                self.mw(addr, value);
            }
            Opcode::SW => {
                let (rs1, rs2, imm) = instruction.s_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                let addr = a.wrapping_add(c);
                let value = b;
                self.mw(addr, value);
            }

            // B-type instructions.
            Opcode::BEQ => {
                let (rs1, rs2, imm) = instruction.b_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                if a == b {
                    self.pc = self.pc.wrapping_add(c);
                }
            }
            Opcode::BNE => {
                let (rs1, rs2, imm) = instruction.b_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                if self.rr(rs1) != self.rr(rs2) {
                    self.pc = self.pc.wrapping_add(imm);
                }
            }
            Opcode::BLT => {
                let (rs1, rs2, imm) = instruction.b_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                if (self.rr(rs1) as i32) < (self.rr(rs2) as i32) {
                    self.pc = self.pc.wrapping_add(imm);
                }
            }
            Opcode::BGE => {
                let (rs1, rs2, imm) = instruction.b_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                if (self.rr(rs1) as i32) >= (self.rr(rs2) as i32) {
                    self.pc = self.pc.wrapping_add(imm);
                }
            }
            Opcode::BLTU => {
                let (rs1, rs2, imm) = instruction.b_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                if self.rr(rs1) < self.rr(rs2) {
                    self.pc = self.pc.wrapping_add(imm);
                }
            }
            Opcode::BGEU => {
                let (rs1, rs2, imm) = instruction.b_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                if self.rr(rs1) >= self.rr(rs2) {
                    self.pc = self.pc.wrapping_add(imm);
                }
            }

            // Jump instructions.
            Opcode::JAL => {
                let (rd, imm) = instruction.j_type();
                (b, c) = (imm, 0);
                a = self.pc + 4;
                self.rw(rd, a);
                self.pc = self.pc.wrapping_add(imm);
            }
            Opcode::JALR => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                a = self.pc + 4;
                self.rw(rd, a);
                self.pc = b.wrapping_add(c);
            }

            // Upper immediate instructions.
            Opcode::LUI => {
                let (rd, imm) = instruction.u_type();
                (b, c) = (imm, 12); // Note that we'll special-case this in the CPU table
                a = b << 12;
                self.rw(rd, a);
            }
            Opcode::AUIPC => {
                let (rd, imm) = instruction.u_type();
                (b, c) = (imm, imm << 12); // Note that we'll special-case this in the CPU table
                a = self.pc.wrapping_add(b << 12);
                self.rw(rd, a);
            }

            // System instructions.
            Opcode::ECALL => {
                todo!()
            }
            Opcode::EBREAK => {
                todo!()
            }

            // Multiply instructions.
            Opcode::MUL => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = b.wrapping_mul(c);
                self.rw(rd, a);
            }
            Opcode::MULH => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = ((b as i64).wrapping_mul(c as i64) >> 32) as u32;
                self.rw(rd, a);
            }
            Opcode::MULSU => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = ((b as i64).wrapping_mul(c as i64) >> 32) as u32;
                self.rw(rd, a);
            }
            Opcode::MULU => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = ((b as u64).wrapping_mul(c as u64) >> 32) as u32;
                self.rw(rd, a);
            }
            Opcode::DIV => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = (b as i32).wrapping_div(c as i32) as u32;
                self.rw(rd, a);
            }
            Opcode::DIVU => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = b.wrapping_div(c);
                self.rw(rd, a);
            }
            Opcode::REM => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1) as i32, self.rr(rs2) as i32);
                let a = (b as i32).wrapping_rem(c as i32) as u32;
                self.rw(rd, a);
            }
            Opcode::REMU => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = b.wrapping_rem(c);
                self.rw(rd, a);
            }
        }

        // Emit the CPU event for this cycle.
        self.emit_cpu(self.clk, pc, instruction, a, b, c);
    }

    /// Execute the program.
    pub fn run(&mut self) {
        // Set %x2 to the size of memory when the CPU is initialized.
        self.rw(Register::X2, 1024 * 1024 * 8);

        while self.pc < (self.program.len() * 4) as u32 {
            // Fetch the instruction at the current program counter.
            let instruction = self.fetch();

            // Execute the instruction.
            self.execute(instruction);

            // Increment the program counter by 4.
            self.pc = self.pc + 4;

            // Increment the clock.
            self.clk += 1;
        }
    }

    /// Prove the program.
    #[allow(unused)]
    pub fn prove<F, EF, SC>(&mut self, config: &SC, challenger: &mut SC::Challenger)
    where
        F: PrimeField + TwoAdicField,
        EF: ExtensionField<F>,
        SC: StarkConfig<Val = F, Challenge = EF>,
    {
        // Initialize chips.
        let program = ProgramChip::new();
        let cpu = CpuChip::new();
        let add = AddChip::new();
        let sub = SubChip::new();
        let bitwise = BitwiseChip::new();
        let chips: [&dyn Chip<F>; 5] = [&program, &cpu, &add, &sub, &bitwise];

        // For each chip, generate the trace.
        let traces = chips.map(|chip| chip.generate_trace(self));

        // For each trace, compute the degree.
        let degrees: [usize; 5] = traces
            .iter()
            .map(|trace| trace.height())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let log_degrees = degrees.map(|d| log2_strict_usize(d));
        let g_subgroups = log_degrees.map(|log_deg| SC::Val::two_adic_generator(log_deg));

        // Commit to the batch of traces.
        let (main_commit, main_data) = config.pcs().commit_batches(traces.to_vec());
        challenger.observe(main_commit);

        // Obtain the challenges used for the permutation argument.
        let mut permutation_challenges: Vec<EF> = Vec::new();
        for _ in 0..2 {
            permutation_challenges.push(challenger.sample_ext_element());
        }

        // Generate the permutation traces.
        let permutation_traces = chips
            .into_iter()
            .enumerate()
            .map(|(i, chip)| {
                generate_permutation_trace(chip, &traces[i], permutation_challenges.clone())
            })
            .collect::<Vec<_>>();

        // Commit to the permutation traces.
        let flattened_permutation_traces = permutation_traces
            .iter()
            .map(|trace| trace.flatten_to_base())
            .collect::<Vec<_>>();
        let (permutation_commit, permutation_data) =
            config.pcs().commit_batches(flattened_permutation_traces);
        challenger.observe(permutation_commit);

        // TODO: ADD QUOTIENT COMMITMENTS
        let zeta: SC::Challenge = challenger.sample_ext_element();
        let zeta_and_next = [zeta, zeta * g_subgroups[0]];
        let prover_data_and_points = [
            (&main_data, zeta_and_next.as_slice()),
            (&permutation_data, zeta_and_next.as_slice()),
        ];
        let (openings, opening_proof) = config
            .pcs()
            .open_multi_batches(&prover_data_and_points, challenger);

        // Check that the table-specific constraints are correct for each chip.
        debug_constraints(
            &program,
            &traces[0],
            &permutation_traces[0],
            &permutation_challenges,
        );

        // Check the permutation argument between all tables.
        debug_cumulative_sums::<F, EF>(&permutation_traces[..]);
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use p3_challenger::DuplexChallenger;
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::Field;

    use p3_baby_bear::BabyBear;
    use p3_field::extension::BinomialExtensionField;
    use p3_fri::{FriBasedPcs, FriConfigImpl, FriLdt};
    use p3_keccak::Keccak256Hash;
    use p3_ldt::QuotientMmcs;
    use p3_mds::coset_mds::CosetMds;
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_poseidon2::{DiffusionMatrixBabybear, Poseidon2};
    use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
    use p3_uni_stark::StarkConfigImpl;
    use rand::thread_rng;

    use crate::{runtime::Register, Runtime};

    use super::{Instruction, Opcode};

    #[test]
    fn PROVE() {
        type Val = BabyBear;
        type Domain = Val;
        type Challenge = BinomialExtensionField<Val, 4>;
        type PackedChallenge = BinomialExtensionField<<Domain as Field>::Packing, 4>;

        type MyMds = CosetMds<Val, 16>;
        let mds = MyMds::default();

        type Perm = Poseidon2<Val, MyMds, DiffusionMatrixBabybear, 16, 5>;
        let perm = Perm::new_from_rng(8, 22, mds, DiffusionMatrixBabybear, &mut thread_rng());

        type MyHash = SerializingHasher32<Keccak256Hash>;
        let hash = MyHash::new(Keccak256Hash {});

        type MyCompress = CompressionFunctionFromHasher<Val, MyHash, 2, 8>;
        let compress = MyCompress::new(hash);

        type ValMmcs = FieldMerkleTreeMmcs<Val, MyHash, MyCompress, 8>;
        let val_mmcs = ValMmcs::new(hash, compress);

        type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

        type Dft = Radix2DitParallel;
        let dft = Dft {};

        type Challenger = DuplexChallenger<Val, Perm, 16>;

        type Quotient = QuotientMmcs<Domain, Challenge, ValMmcs>;
        type MyFriConfig = FriConfigImpl<Val, Challenge, Quotient, ChallengeMmcs, Challenger>;
        let fri_config = MyFriConfig::new(40, challenge_mmcs);
        let ldt = FriLdt { config: fri_config };

        type Pcs = FriBasedPcs<MyFriConfig, ValMmcs, Dft, Challenger>;
        type MyConfig = StarkConfigImpl<Val, Challenge, PackedChallenge, Pcs, Challenger>;

        let pcs = Pcs::new(dft, val_mmcs, ldt);
        let config = StarkConfigImpl::new(pcs);
        let mut challenger = Challenger::new(perm.clone());

        // main:
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     add x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::ADD, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        runtime.prove::<_, _, MyConfig>(&config, &mut challenger);
        assert_eq!(runtime.registers()[Register::X31 as usize], 42);
    }

    #[test]
    fn ADD() {
        // main:
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     add x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::ADD, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        // runtime.prove::<BabyBear>();
        assert_eq!(runtime.registers()[Register::X31 as usize], 42);
    }

    #[test]
    fn SUB() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sub x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::SUB, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        // runtime.prove::<BabyBear>();
        assert_eq!(runtime.registers()[Register::X31 as usize], 32);
    }

    #[test]
    fn XOR() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     xor x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::XOR, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        // runtime.prove::<BabyBear>();
        assert_eq!(runtime.registers()[Register::X31 as usize], 32);
    }

    #[test]
    fn OR() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     or x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::OR, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        // runtime.prove::<BabyBear>();
        assert_eq!(runtime.registers()[Register::X31 as usize], 37);
    }

    #[test]
    fn AND() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     and x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::AND, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        // runtime.prove::<BabyBear>();
        assert_eq!(runtime.registers()[Register::X31 as usize], 5);
    }

    #[test]
    fn SLL() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sll x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::SLL, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 1184);
    }

    #[test]
    fn SRL() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     srl x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::SRL, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 1);
    }

    #[test]
    fn SRA() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sra x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::SRA, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 1);
    }

    #[test]
    fn SLT() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     slt x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::SLT, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 0);
    }

    #[test]
    fn SLTU() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sltu x31, x30, x29
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::SLTU, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 0);
    }

    #[test]
    fn ADDI() {
        //     addi x29, x0, 5
        //     addi x30, x29, 37
        //     addi x31, x30, 42
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 29, 37),
            Instruction::new(Opcode::ADDI, 31, 30, 42),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 84);
    }

    #[test]
    fn XORI() {
        //     addi x29, x0, 5
        //     xori x30, x29, 37
        //     xori x31, x30, 42
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::XORI, 30, 29, 37),
            Instruction::new(Opcode::XORI, 31, 30, 42),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        // runtime.prove::<BabyBear>();
        assert_eq!(runtime.registers()[Register::X31 as usize], 10);
    }

    #[test]
    fn ORI() {
        //     addi x29, x0, 5
        //     ori x30, x29, 37
        //     ori x31, x30, 42
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ORI, 30, 29, 37),
            Instruction::new(Opcode::ORI, 31, 30, 42),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        // runtime.prove::<BabyBear>();
        assert_eq!(runtime.registers()[Register::X31 as usize], 47);
    }

    #[test]
    fn ANDI() {
        //     addi x29, x0, 5
        //     andi x30, x29, 37
        //     andi x31, x30, 42
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ANDI, 30, 29, 37),
            Instruction::new(Opcode::ANDI, 31, 30, 42),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        // runtime.prove::<BabyBear>();
        assert_eq!(runtime.registers()[Register::X31 as usize], 0);
    }

    #[test]
    fn SLLI() {
        //     addi x29, x0, 5
        //     slli x31, x29, 37
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::SLLI, 31, 29, 4),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 80);
    }

    #[test]
    fn SRLI() {
        //    addi x29, x0, 5
        //    srli x31, x29, 37
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 42),
            Instruction::new(Opcode::SRLI, 31, 29, 4),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 2);
    }

    #[test]
    fn SRAI() {
        //   addi x29, x0, 5
        //   srai x31, x29, 37
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 42),
            Instruction::new(Opcode::SRAI, 31, 29, 4),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 2);
    }

    #[test]
    fn SLTI() {
        //   addi x29, x0, 5
        //   slti x31, x29, 37
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 42),
            Instruction::new(Opcode::SLTI, 31, 29, 37),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 0);
    }

    #[test]
    fn SLTIU() {
        //   addi x29, x0, 5
        //   sltiu x31, x29, 37
        let program = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 42),
            Instruction::new(Opcode::SLTIU, 31, 29, 37),
        ];
        let mut runtime = Runtime::new(program);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 0);
    }
}
