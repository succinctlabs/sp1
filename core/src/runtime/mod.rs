use std::{
    collections::BTreeMap,
    fmt::{Display, Formatter},
};

use crate::{
    alu::AluEvent,
    memory::{MemOp, MemoryEvent},
};

/// An opcode specifies which operation to execute.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
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
    opcode: Opcode,
    a: u32,
    b: u32,
    c: u32,
}

impl Instruction {
    pub fn new(opcode: Opcode, a: u32, b: u32, c: u32) -> Instruction {
        Instruction { opcode, a, b, c }
    }

    pub fn r_type(&self) -> (Register, Register, Register) {
        (
            Register::from_u32(self.a),
            Register::from_u32(self.b),
            Register::from_u32(self.c),
        )
    }

    pub fn i_type(&self) -> (Register, Register, u32) {
        (
            Register::from_u32(self.a),
            Register::from_u32(self.b),
            self.c,
        )
    }

    pub fn s_type(&self) -> (Register, Register, u32) {
        (
            Register::from_u32(self.a),
            Register::from_u32(self.b),
            self.c,
        )
    }

    pub fn b_type(&self) -> (Register, Register, u32) {
        (
            Register::from_u32(self.a),
            Register::from_u32(self.b),
            self.c,
        )
    }

    pub fn j_type(&self) -> (Register, u32) {
        (Register::from_u32(self.a), self.b)
    }

    pub fn u_type(&self) -> (Register, u32) {
        (Register::from_u32(self.a), self.b)
    }
}

/// A runtime executes a program.
#[derive(Debug)]
pub struct Runtime {
    /// The clock keeps track of how many instructions have been executed.
    clk: u32,

    /// The program counter keeps track of the next instruction.
    pc: u32,

    /// The prgram used during execution.
    program: Vec<Instruction>,

    /// The memory which instructions operate over.
    memory: BTreeMap<u32, u32>,

    /// A trace of the memory events which get emitted during execution.
    memory_events: Vec<MemoryEvent>,

    /// A trace of the ALU events which get emitted during execution.
    alu_events: Vec<AluEvent>,
}

impl Runtime {
    /// Create a new runtime.
    pub fn new(program: Vec<Instruction>) -> Self {
        Self {
            clk: 0,
            pc: 0,
            memory: BTreeMap::new(),
            program,
            memory_events: Vec::new(),
            alu_events: Vec::new(),
        }
    }

    /// Read from memory.
    fn mr(&mut self, addr: u32) -> u32 {
        let value = match self.memory.get(&addr) {
            Some(value) => *value,
            None => 0,
        };
        self.memory_events.push(MemoryEvent {
            clk: self.clk,
            addr,
            op: MemOp::Read,
            value,
        });
        return value;
    }

    /// Write to memory.
    fn mw(&mut self, addr: u32, value: u32) {
        self.memory_events.push(MemoryEvent {
            clk: self.clk,
            addr,
            op: MemOp::Write,
            value,
        });
        self.memory.insert(addr, value);
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
        let addr = 1024 * 1024 * 8 + (register as u32);
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

    /// Emit an ALU event.
    fn emit_alu(&mut self, opcode: Opcode, a: u32, b: u32, c: u32) {
        self.alu_events.push(AluEvent {
            clk: self.clk,
            opcode,
            a,
            b,
            c,
        });
    }

    /// Execute the given instruction over the current state of the runtime.
    fn execute(&mut self, instruction: Instruction) {
        match instruction.opcode {
            // R-type instructions.
            Opcode::ADD => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = b.wrapping_add(c);
                self.rw(rd, a);
                self.emit_alu(Opcode::ADD, a, b, c);
            }
            Opcode::SUB => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = b.wrapping_sub(c);
                self.rw(rd, a);
                self.emit_alu(Opcode::SUB, a, b, c);
            }
            Opcode::XOR => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = b ^ c;
                self.rw(rd, a);
                self.emit_alu(Opcode::XOR, a, b, c);
            }
            Opcode::OR => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = b | c;
                self.rw(rd, a);
                self.emit_alu(Opcode::OR, a, b, c);
            }
            Opcode::AND => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = b & c;
                self.rw(rd, a);
                self.emit_alu(Opcode::AND, a, b, c);
            }
            Opcode::SLL => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = b << c;
                self.rw(rd, a);
                self.emit_alu(Opcode::SLL, a, b, c);
            }
            Opcode::SRL => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = b >> c;
                self.rw(rd, a);
                self.emit_alu(Opcode::SRL, a, b, c);
            }
            Opcode::SRA => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = (b as i32 >> c) as u32;
                self.rw(rd, a);
                self.emit_alu(Opcode::SRA, a, b, c);
            }
            Opcode::SLT => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = if (b as i32) < (c as i32) { 1 } else { 0 };
                self.rw(rd, a);
                self.emit_alu(Opcode::SLT, a, b, c);
            }
            Opcode::SLTU => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = if b < c { 1 } else { 0 };
                self.rw(rd, a);
                self.emit_alu(Opcode::SLTU, a, b, c);
            }

            // I-type instructions.
            Opcode::ADDI => {
                let (rd, rs1, imm) = instruction.i_type();
                let (b, c) = (self.rr(rs1), imm);
                let a = b.wrapping_add(c);
                self.rw(rd, a);
                self.emit_alu(Opcode::ADDI, a, b, c);
            }
            Opcode::XORI => {
                let (rd, rs1, imm) = instruction.i_type();
                let (b, c) = (self.rr(rs1), imm);
                let a = b ^ c;
                self.rw(rd, a);
                self.emit_alu(Opcode::XORI, a, b, c);
            }
            Opcode::ORI => {
                let (rd, rs1, imm) = instruction.i_type();
                let (b, c) = (self.rr(rs1), imm);
                let a = b | c;
                self.rw(rd, a);
                self.emit_alu(Opcode::ORI, a, b, c);
            }
            Opcode::ANDI => {
                let (rd, rs1, imm) = instruction.i_type();
                let (b, c) = (self.rr(rs1), imm);
                let a = b & c;
                self.rw(rd, a);
                self.emit_alu(Opcode::ANDI, a, b, c);
            }
            Opcode::SLLI => {
                let (rd, rs1, imm) = instruction.i_type();
                let (b, c) = (self.rr(rs1), imm);
                let a = b << c;
                self.rw(rd, a);
                self.emit_alu(Opcode::SLLI, a, b, c);
            }
            Opcode::SRLI => {
                let (rd, rs1, imm) = instruction.i_type();
                let (b, c) = (self.rr(rs1), imm);
                let a = b >> c;
                self.rw(rd, a);
                self.emit_alu(Opcode::SRLI, a, b, c);
            }
            Opcode::SRAI => {
                let (rd, rs1, imm) = instruction.i_type();
                let (b, c) = (self.rr(rs1), imm);
                let a = (b as i32 >> c) as u32;
                self.rw(rd, a);
                self.emit_alu(Opcode::SRAI, a, b, c);
            }
            Opcode::SLTI => {
                let (rd, rs1, imm) = instruction.i_type();
                let (b, c) = (self.rr(rs1), imm);
                let a = if (b as i32) < (c as i32) { 1 } else { 0 };
                self.rw(rd, a);
                self.emit_alu(Opcode::SLTI, a, b, c);
            }
            Opcode::SLTIU => {
                let (rd, rs1, imm) = instruction.i_type();
                let (b, c) = (self.rr(rs1), imm);
                let a = if b < c { 1 } else { 0 };
                self.rw(rd, a);
                self.emit_alu(Opcode::SLTIU, a, b, c);
            }
            Opcode::LB => {
                let (rd, rs1, imm) = instruction.i_type();
                let addr = self.rr(rs1).wrapping_add(imm);
                let value = (self.mr(addr) as i8) as u32;
                self.rw(rd, value);
            }
            Opcode::LH => {
                let (rd, rs1, imm) = instruction.i_type();
                let addr = self.rr(rs1).wrapping_add(imm);
                let value = (self.mr(addr) as i16) as u32;
                self.rw(rd, value);
            }
            Opcode::LW => {
                let (rd, rs1, imm) = instruction.i_type();
                let addr = self.rr(rs1).wrapping_add(imm);
                let value = self.mr(addr);
                self.rw(rd, value);
            }
            Opcode::LBU => {
                let (rd, rs1, imm) = instruction.i_type();
                let addr = self.rr(rs1).wrapping_add(imm);
                let value = (self.mr(addr) as u8) as u32;
                self.rw(rd, value);
            }
            Opcode::LHU => {
                let (rd, rs1, imm) = instruction.i_type();
                let addr = self.rr(rs1).wrapping_add(imm);
                let value = (self.mr(addr) as u16) as u32;
                self.rw(rd, value);
            }

            // S-type instructions.
            Opcode::SB => {
                let (rs1, rs2, imm) = instruction.s_type();
                let addr = self.rr(rs1).wrapping_add(imm);
                let value = (self.rr(rs2) as u8) as u32;
                self.mw(addr, value);
            }
            Opcode::SH => {
                let (rs1, rs2, imm) = instruction.s_type();
                let addr = self.rr(rs1).wrapping_add(imm);
                let value = (self.rr(rs2) as u16) as u32;
                self.mw(addr, value);
            }
            Opcode::SW => {
                let (rs1, rs2, imm) = instruction.s_type();
                let addr = self.rr(rs1).wrapping_add(imm);
                let value = self.rr(rs2);
                self.mw(addr, value);
            }

            // B-type instructions.
            Opcode::BEQ => {
                let (rs1, rs2, imm) = instruction.b_type();
                if self.rr(rs1) == self.rr(rs2) {
                    self.pc = self.pc.wrapping_add(imm);
                }
            }
            Opcode::BNE => {
                let (rs1, rs2, imm) = instruction.b_type();
                if self.rr(rs1) != self.rr(rs2) {
                    self.pc = self.pc.wrapping_add(imm);
                }
            }
            Opcode::BLT => {
                let (rs1, rs2, imm) = instruction.b_type();
                if (self.rr(rs1) as i32) < (self.rr(rs2) as i32) {
                    self.pc = self.pc.wrapping_add(imm);
                }
            }
            Opcode::BGE => {
                let (rs1, rs2, imm) = instruction.b_type();
                if (self.rr(rs1) as i32) >= (self.rr(rs2) as i32) {
                    self.pc = self.pc.wrapping_add(imm);
                }
            }
            Opcode::BLTU => {
                let (rs1, rs2, imm) = instruction.b_type();
                if self.rr(rs1) < self.rr(rs2) {
                    self.pc = self.pc.wrapping_add(imm);
                }
            }
            Opcode::BGEU => {
                let (rs1, rs2, imm) = instruction.b_type();
                if self.rr(rs1) >= self.rr(rs2) {
                    self.pc = self.pc.wrapping_add(imm);
                }
            }

            // Jump instructions.
            Opcode::JAL => {
                let (rd, imm) = instruction.j_type();
                self.rw(rd, self.pc + 4);
                self.pc = self.pc.wrapping_add(imm);
            }
            Opcode::JALR => {
                let (rd, rs1, imm) = instruction.i_type();
                self.rw(rd, self.pc + 4);
                self.pc = self.rr(rs1).wrapping_add(imm);
            }

            // Upper immediate instructions.
            Opcode::LUI => {
                let (rd, imm) = instruction.u_type();
                self.rw(rd, imm << 12);
            }
            Opcode::AUIPC => {
                let (rd, imm) = instruction.u_type();
                self.rw(rd, self.pc.wrapping_add(imm << 12));
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
                self.emit_alu(Opcode::MUL, a, b, c);
            }
            Opcode::MULH => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = ((b as i64).wrapping_mul(c as i64) >> 32) as u32;
                self.rw(rd, a);
                self.emit_alu(Opcode::MULH, a, b, c);
            }
            Opcode::MULSU => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = ((b as i64).wrapping_mul(c as i64) >> 32) as u32;
                self.rw(rd, a);
                self.emit_alu(Opcode::MULSU, a, b, c);
            }
            Opcode::MULU => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = ((b as u64).wrapping_mul(c as u64) >> 32) as u32;
                self.rw(rd, a);
                self.emit_alu(Opcode::MULU, a, b, c);
            }
            Opcode::DIV => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = (b as i32).wrapping_div(c as i32) as u32;
                self.rw(rd, a);
                self.emit_alu(Opcode::DIV, a, b, c);
            }
            Opcode::DIVU => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = b.wrapping_div(c);
                self.rw(rd, a);
                self.emit_alu(Opcode::DIVU, a, b, c);
            }
            Opcode::REM => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1) as i32, self.rr(rs2) as i32);
                let a = (b as i32).wrapping_rem(c as i32) as u32;
                self.rw(rd, a);
                self.emit_alu(Opcode::REM, a, b as u32, c as u32);
            }
            Opcode::REMU => {
                let (rd, rs1, rs2) = instruction.r_type();
                let (b, c) = (self.rr(rs1), self.rr(rs2));
                let a = b.wrapping_rem(c);
                self.rw(rd, a);
                self.emit_alu(Opcode::REMU, a, b, c);
            }
        }
    }

    /// Executes the code.
    pub fn run(&mut self) {
        // Set %x2 to the size of memory when the CPU is initialized.
        self.rw(Register::X2, 1024 * 1024 * 8);

        while self.pc < (self.program.len() * 4) as u32 {
            // Fetch the instruction at the current program counter.
            let instruction = self.fetch();

            // Increment the program counter by 4.
            self.pc = self.pc + 4;

            // Execute the instruction.
            self.execute(instruction);

            // Increment the clock.
            self.clk += 1;
        }
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use crate::{runtime::Register, Runtime};

    use super::{Instruction, Opcode};

    #[test]
    fn ADD() {
        // main:
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     add x31, x30, x29
        let code = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::ADD, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(code);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 42);
    }

    #[test]
    fn SUB() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sub x31, x30, x29
        let code = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::SUB, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(code);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 32);
    }

    #[test]
    fn XOR() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     xor x31, x30, x29
        let code = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::XOR, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(code);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 32);
    }

    #[test]
    fn OR() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     or x31, x30, x29
        let code = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::OR, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(code);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 37);
    }

    #[test]
    fn AND() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     and x31, x30, x29
        let code = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::AND, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(code);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 5);
    }

    #[test]
    fn SLL() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sll x31, x30, x29
        let code = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::SLL, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(code);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 1184);
    }

    #[test]
    fn SRL() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     srl x31, x30, x29
        let code = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::SRL, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(code);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 1);
    }

    #[test]
    fn SRA() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sra x31, x30, x29
        let code = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::SRA, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(code);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 1);
    }

    #[test]
    fn SLT() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     slt x31, x30, x29
        let code = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::SLT, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(code);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 0);
    }

    #[test]
    fn SLTU() {
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     sltu x31, x30, x29
        let code = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 0, 37),
            Instruction::new(Opcode::SLTU, 31, 30, 29),
        ];
        let mut runtime = Runtime::new(code);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 0);
    }

    #[test]
    fn ADDI() {
        //     addi x29, x0, 5
        //     addi x30, x29, 37
        //     addi x31, x30, 42
        let code = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ADDI, 30, 29, 37),
            Instruction::new(Opcode::ADDI, 31, 30, 42),
        ];
        let mut runtime = Runtime::new(code);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 84);
    }

    #[test]
    fn XORI() {
        //     addi x29, x0, 5
        //     xori x30, x29, 37
        //     xori x31, x30, 42
        let code = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::XORI, 30, 29, 37),
            Instruction::new(Opcode::XORI, 31, 30, 42),
        ];
        let mut runtime = Runtime::new(code);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 10);
    }

    #[test]
    fn ORI() {
        //     addi x29, x0, 5
        //     ori x30, x29, 37
        //     ori x31, x30, 42
        let code = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ORI, 30, 29, 37),
            Instruction::new(Opcode::ORI, 31, 30, 42),
        ];
        let mut runtime = Runtime::new(code);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 47);
    }

    #[test]
    fn ANDI() {
        //     addi x29, x0, 5
        //     andi x30, x29, 37
        //     andi x31, x30, 42
        let code = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::ANDI, 30, 29, 37),
            Instruction::new(Opcode::ANDI, 31, 30, 42),
        ];
        let mut runtime = Runtime::new(code);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 0);
    }

    #[test]
    fn SLLI() {
        //     addi x29, x0, 5
        //     slli x31, x29, 37
        let code = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5),
            Instruction::new(Opcode::SLLI, 31, 29, 4),
        ];
        let mut runtime = Runtime::new(code);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 80);
    }

    #[test]
    fn SRLI() {
        //    addi x29, x0, 5
        //    srli x31, x29, 37
        let code = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 42),
            Instruction::new(Opcode::SRLI, 31, 29, 4),
        ];
        let mut runtime = Runtime::new(code);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 2);
    }

    #[test]
    fn SRAI() {
        //   addi x29, x0, 5
        //   srai x31, x29, 37
        let code = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 42),
            Instruction::new(Opcode::SRAI, 31, 29, 4),
        ];
        let mut runtime = Runtime::new(code);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 2);
    }

    #[test]
    fn SLTI() {
        //   addi x29, x0, 5
        //   slti x31, x29, 37
        let code = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 42),
            Instruction::new(Opcode::SLTI, 31, 29, 37),
        ];
        let mut runtime = Runtime::new(code);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 0);
    }

    #[test]
    fn SLTIU() {
        //   addi x29, x0, 5
        //   sltiu x31, x29, 37
        let code = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 42),
            Instruction::new(Opcode::SLTIU, 31, 29, 37),
        ];
        let mut runtime = Runtime::new(code);
        runtime.run();
        assert_eq!(runtime.registers()[Register::X31 as usize], 0);
    }
}
