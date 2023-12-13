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
    mem,
};

use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

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

    UNIMP = 47,
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

            Opcode::UNIMP => write!(f, "unimp"),
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

/// An operand that can either be a register or an immediate value.
#[derive(Debug)]
pub enum RegisterOrImmediate {
    Register(Register),
    Immediate(i32),
}

/// An instruction specifies an operation to execute and the operands.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Instruction {
    pub opcode: Opcode,
    pub op_a: u32,
    pub op_b: u32,
    pub op_c: u32,
}

/// A runtime executes a program.
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

/// Take the from-th bit of a and return a number whose to-th bit is set. The
/// least significant bit is the 0th bit.
fn bit_op(a: u32, from: usize, to: usize) -> u32{
    ((a >> from) & 1) << to
}

/// Decode a binary representation of a RISC-V instruction and decode it.
/// 
/// Refer to P.104 of The RISC-V Instruction Set Manual for the exact
/// specification.
pub fn create_instruction(input: u32) -> Instruction {
    if input == 0xc0001073 {
        // See https://github.com/riscv-non-isa/riscv-asm-manual/blob/master/riscv-asm.md#instruction-aliases
        return Instruction {
            opcode: Opcode::UNIMP,
            a: 0,
            b: 0,
            c: 0,
        };
    }
    
    let op_code = input & 0b1111111;
    let rd = (input >> 7) & 0b11111;
    let funct3 = (input >> 12) & 0b111;
    let rs1 = (input >> 15) & 0b11111;
    let rs2 = (input >> 20) & 0b11111;
    let funct7 = (input >> 25) & 0b1111111;
    let imm_11_0 = (input >> 20) & 0b111111111111;
    let imm_11_5 = (input >> 25) & 0b1111111;
    let imm_4_0 = (input >> 7) & 0b11111;
    let imm_31_12 = (input >> 12) & 0xfffff; // 20-bit mask

    match op_code {
        0b0110111 => {
            // LUI
            Instruction {
                opcode: Opcode::LUI,
                a: rd,
                b: imm_31_12,
                c: 0,
            }
        }
        0b0010111 => {
            // AUIPC
            Instruction {
                opcode: Opcode::AUIPC,
                a: rd,
                b: imm_31_12,
                c: 0,
            }
        }
        0b1101111 => {
            // JAL
            let mut perm = Vec::<(usize, usize)>::new();
            perm.push((31, 20));
            for i in 1..11 {
                perm.push((20 + i, i));
            }
            perm.push((20, 11));
            for i in 12..20 {
                perm.push((i, i));
            }
            let mut imm = 0;
            for p in perm.iter() {
                imm |= bit_op(input, p.0, p.1);
            }

            Instruction {
                opcode: Opcode::JAL,
                a: rd,
                b: imm,
                c: 0,
            }
        }
        0b1100111 => {
            // JALR
            Instruction {
                opcode: Opcode::AUIPC,
                a: rd,
                b: imm_11_0,
                c: 0,
            }
        }
        0b1100011 => {
            // BEQ, BNE, BLT, BGE, BLTU, BGEU
            let opcode = match funct3 {
                0b000 => Opcode::BEQ,
                0b001 => Opcode::BNE,
                0b100 => Opcode::BLT,
                0b101 => Opcode::BGE,
                0b110 => Opcode::BLTU,
                0b111 => Opcode::BGEU,
                _ => panic!("Invalid funct3 {}", funct3),
            };
            // Concatenate to form the immediate value
            let mut imm = bit_op(input, 31, 12);
            
            imm |= bit_op(input, 30, 10);
            imm |= bit_op(input, 29, 9);
            imm |= bit_op(input, 28, 8);
            imm |= bit_op(input, 27, 7);
            imm |= bit_op(input, 26, 6);
            imm |= bit_op(input, 25, 5);
            imm |= bit_op(input, 11, 4);
            imm |= bit_op(input, 10, 3);
            imm |= bit_op(input, 9, 2);
            imm |= bit_op(input, 8, 1);
            imm |= bit_op(input, 7, 11);

            Instruction {
                opcode,
                a: rs1,
                b: rs2,
                c: imm,
            }
        }
        0b0000011 => {
            // LB, LH, LW, LBU, LHU
            let opcode = match funct3 {
                0b000 => Opcode::LB,
                0b001 => Opcode::LH,
                0b010 => Opcode::LW,
                0b100 => Opcode::LBU,
                0b101 => Opcode::LHU,
                _ => panic!("Invalid funct3 {}", funct3),
            };
            Instruction {
                opcode,
                a: rd,
                b: rs1,
                c: imm_11_0,
            }
        }
        0b0100011 => {
            // SB, SH, SW
            let opcode = match funct3 {
                0b000 => Opcode::SB,
                0b001 => Opcode::SH,
                0b010 => Opcode::SW,
                _ => panic!("Invalid funct3 {}", funct3),
            };
            let imm = (imm_11_5 << 5) | imm_4_0;
            Instruction {
                opcode,
                a: rs2,
                b: rs1,
                c: imm,
            }
        }
        0b0010011 => {
            // ADDI, SLTI, SLTIU, XORI, ORI, ANDI, SLLI, SRLI, SRAI
            let opcode = match funct3 {
                0b000 => Opcode::ADDI,
                0b010 => Opcode::SLTI,
                0b011 => Opcode::SLTIU,
                0b100 => Opcode::XORI,
                0b110 => Opcode::ORI,
                0b111 => Opcode::ANDI,
                0b001 => Opcode::SLLI,
                0b101 => {
                    if funct7 == 0 {
                        Opcode::SRLI
                    } else if funct7 == 0b0100000 {
                        Opcode::SRAI
                    } else {
                        panic!("Invalid funct7 {}", funct7);
                    }
                }
                _ => panic!("Invalid funct3 {}", funct3),
            };
            if funct3 == 0b001 || funct3 == 0b101 {
                Instruction {
                    opcode,
                    a: rd,
                    b: rs1,
                    c: (input >> 20) & 0b1111,
                }
            } else {
                Instruction {
                    opcode,
                    a: rd,
                    b: rs1,
                    c: imm_11_0,
                }
            }
        }
        0b0110011 => {
            // ADD, SUB, SLL, SLT, SLTU, XOR, SRL, SRA, OR, AND
            let opcode = match funct3 {
                0b000 => {
                    if funct7 == 0 {
                        Opcode::ADD
                    } else if funct7 == 0b0100000 {
                        Opcode::SUB
                    } else {
                        panic!("Invalid funct7 {}", funct7);
                    }
                }
                0b001 => Opcode::SLL,
                0b010 => Opcode::SLT,
                0b011 => Opcode::SLTU,
                0b100 => Opcode::XOR,
                0b101 => {
                    if funct7 == 0 {
                        Opcode::SRL
                    } else if funct7 == 0b0100000 {
                        Opcode::SRA
                    } else {
                        panic!("Invalid funct7 {}", funct7);
                    }
                }
                0b110 => Opcode::OR,
                0b111 => Opcode::AND,
                _ => panic!("Invalid funct3 {}", funct3),
            };
            Instruction {
                opcode,
                a: rd,
                b: rs1,
                c: rs2,
            }
        }
        0b0001111 => {
            // FENCE, FENCE.I, ECALL, EBREAK
            let opcode = match funct3 {
                0b000 => panic!("FENCE not implemented"),
                0b001 => panic!("FENCE.I not implemented"),
                0b111 => {
                    if funct7 == 0 {
                        Opcode::ECALL
                    } else if funct7 == 0b0000001 {
                        Opcode::EBREAK
                    } else {
                        panic!("Invalid funct7 {}", funct7);
                    }
                }
                _ => panic!("Invalid funct3 {}", funct3),
            };
            Instruction {
                opcode,
                a: 0,
                b: 0,
                c: 0,
            }
        }
        0b1110011 => {
            panic!("CSRRW, CSRRS, CSRRC, CSRRWI, CSRRSI, CSRRCI not implemented {}", input);
        }
        opcode => {
            todo!("opcode {} is invalid", opcode);
        }
    }
}

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
    fn emit_cpu(
        &mut self,
        clk: u32,
        pc: u32,
        instruction: Instruction,
        a: u32,
        b: u32,
        c: u32,
        memory_value: Option<u32>,
    ) {
        self.cpu_events.push(CpuEvent {
            clk: clk,
            pc: pc,
            instruction,
            a,
            b,
            c,
            memory_value,
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
        let (mut a, mut b, mut c, mut memory_value): (u32, u32, u32, Option<u32>) =
            (u32::MAX, u32::MAX, u32::MAX, None);
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
                memory_value = Some(self.mr(addr));
                a = (memory_value.unwrap() as i8) as u32;
                self.rw(rd, a);
            }
            Opcode::LH => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                let addr = b.wrapping_add(c);
                memory_value = Some(self.mr(addr));
                a = (memory_value.unwrap() as i16) as u32;
                self.rw(rd, a);
            }
            Opcode::LW => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                let addr = b.wrapping_add(c);
                memory_value = Some(self.mr(addr));
                a = memory_value.unwrap();
                self.rw(rd, a);
            }
            Opcode::LBU => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                let addr = b.wrapping_add(c);
                memory_value = Some(self.mr(addr));
                let a = (memory_value.unwrap() as u8) as u32;
                self.rw(rd, a);
            }
            Opcode::LHU => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1), imm);
                let addr = b.wrapping_add(c);
                memory_value = Some(self.mr(addr));
                let a = (memory_value.unwrap() as u16) as u32;
                self.rw(rd, a);
            }

            // S-type instructions.
            Opcode::SB => {
                let (rs1, rs2, imm) = instruction.s_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                let addr = b.wrapping_add(c);
                let value = (a as u8) as u32;
                memory_value = Some(value);
                self.mw(addr, value);
            }
            Opcode::SH => {
                let (rs1, rs2, imm) = instruction.s_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                let addr = b.wrapping_add(c);
                let value = (a as u16) as u32;
                memory_value = Some(value);
                self.mw(addr, value);
            }
            Opcode::SW => {
                let (rs1, rs2, imm) = instruction.s_type();
                (a, b, c) = (self.rr(rs1), self.rr(rs2), imm);
                let addr = b.wrapping_add(c);
                let value = a;
                memory_value = Some(value);
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
            Opcode::UNIMP => {
                println!("UNIMP encountered, ignoring");
            }
        }

        // Emit the CPU event for this cycle.
        self.emit_cpu(self.clk, pc, instruction, a, b, c, memory_value);
    }

    /// Execute the program.
    pub fn run(&mut self) {
        // Set %x2 to the size of memory when the CPU is initialized.
        self.rw(Register::X2, 1024 * 1024 * 8);

        while self.pc < (self.program.len() * 4) as u32 {
            // Fetch the instruction at the current program counter.
            let instruction = self.fetch();
            println!("pc = {}, instruction = {:?}", self.pc, instruction);

            // Execute the instruction.
            self.execute(instruction);

            println!("{:?}", self.cpu_events.last().unwrap());

            // Increment the program counter by 4.
            self.pc = self.pc + 4;

            // Increment the clock.
            self.clk += 1;

            if self.clk > 20 {
                break;
            }
        }
    }

    /// Prove the program.
    #[allow(unused)]
    pub fn prove<F: PrimeField>(&mut self) {
        // Initialize chips.
        let program = ProgramChip::new();
        let cpu = CpuChip::new();
        let add = AddChip::new();
        let sub = SubChip::new();
        let bitwise = BitwiseChip::new();

        // Generate the trace for the program chip.
        let program_trace: RowMajorMatrix<F> = program.generate_trace(self);

        // Generate the trace for the CPU chip and also emit auxiliary events.
        let cpu_trace: RowMajorMatrix<F> = cpu.generate_trace(self);

        // Generate the trace of the add chip.
        let add_trace: RowMajorMatrix<F> = add.generate_trace(self);

        // Generate the trace of the sub chip.
        let sub_trace: RowMajorMatrix<F> = sub.generate_trace(self);

        // Generate the trace of the bitwise chip.
        let bitwise_trace: RowMajorMatrix<F> = bitwise.generate_trace(self);

        // Generate the proof.
        // multiprove(vec![program, cpu, memory, alu];
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
pub mod tests {
    use p3_baby_bear::BabyBear;

    use crate::{runtime::{Register, create_instruction}, Runtime};

    use super::{Instruction, Opcode};

    pub fn get_simple_program() -> Vec<Instruction> {
        // int main() {
        //     int a = 5;
        //     int b = 8;
        //     int result = a + b;
        //     return 0;
        //   }
        // main:
        // addi    sp,sp,-32
        // sw      s0,28(sp)
        // addi    s0,sp,32
        // li      a5,5
        // sw      a5,-20(s0)
        // li      a5,8
        // sw      a5,-24(s0)
        // lw      a4,-20(s0)
        // lw      a5,-24(s0)
        // add     a5,a4,a5
        // sw      a5,-28(s0)
        // lw      a5,-28(s0)
        // mv      a0,a5
        // lw      s0,28(sp)
        // addi    sp,sp,32
        // jr      ra
        // Mapping taken from here: https://en.wikichip.org/wiki/risc-v/registers
        let SP = Register::X2 as u32;
        let X0 = Register::X0 as u32;
        let S0 = Register::X8 as u32;
        let A0 = Register::X10 as u32;
        let A5 = Register::X15 as u32;
        let A4 = Register::X14 as u32;
        let RA = Register::X1 as u32;
        let code = vec![
            Instruction::new(Opcode::ADDI, SP, SP, (-32i32) as u32),
            Instruction::new(Opcode::SW, S0, SP, 28),
            Instruction::new(Opcode::ADDI, S0, SP, 32),
            Instruction::new(Opcode::ADDI, A5, X0, 5),
            Instruction::new(Opcode::SW, A5, S0, (-20i32) as u32),
            Instruction::new(Opcode::ADDI, A5, X0, 8),
            Instruction::new(Opcode::SW, A5, S0, (-24i32) as u32),
            Instruction::new(Opcode::LW, A4, S0, (-20i32) as u32),
            Instruction::new(Opcode::LW, A5, S0, (-24i32) as u32),
            Instruction::new(Opcode::ADD, A5, A4, A5),
            Instruction::new(Opcode::SW, A5, S0, (-28i32) as u32),
            Instruction::new(Opcode::LW, A5, S0, (-28i32) as u32),
            Instruction::new(Opcode::ADDI, A0, A5, 0),
            Instruction::new(Opcode::LW, S0, SP, 28),
            Instruction::new(Opcode::ADDI, SP, SP, 32),
            // Instruction::new(Opcode::JALR, X0, RA, 0), // Commented this out because JAL is not working properly right now.
        ];
        code
    }

    #[test]
    fn SIMPLE_PROGRAM() {
        let code = get_simple_program();
        let mut runtime: Runtime = Runtime::new(code);
        runtime.run();
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
        runtime.prove::<BabyBear>();
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
        runtime.prove::<BabyBear>();
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
        runtime.prove::<BabyBear>();
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
        runtime.prove::<BabyBear>();
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
        runtime.prove::<BabyBear>();
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
        runtime.prove::<BabyBear>();
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
        runtime.prove::<BabyBear>();
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
        runtime.prove::<BabyBear>();
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

    fn create_instruction_unit_test(input: u32, opcode: Opcode, rd: u32, rs1: u32, rs2: u32) {
        let exp = Instruction::new(opcode, rd, rs1, rs2);
        let got = create_instruction(input);
        assert_eq!(exp, got);
    }
    #[test]
    fn create_instruction_test() {
        // https://github.com/riscv/riscv-tests
        create_instruction_unit_test(0x00c58633, Opcode::ADD, 12, 11, 12);
        create_instruction_unit_test(0x00d506b3, Opcode::ADD, 13, 10, 13);
        create_instruction_unit_test(0x00a70533, Opcode::ADD, 10, 14, 10);
        create_instruction_unit_test(0xffffe517, Opcode::AUIPC, 10,0xffffe, 0);
        create_instruction_unit_test(0xfffff797, Opcode::AUIPC, 15,0xfffff, 0);
        create_instruction_unit_test(0xfffff797, Opcode::AUIPC, 15,0xfffff, 0);
        create_instruction_unit_test(0x00200793, Opcode::ADDI, 15,0,2);
        create_instruction_unit_test(0x00000013, Opcode::ADDI, 0,0,0);
        create_instruction_unit_test(0x00000013, Opcode::ADDI, 0,0,0);
        create_instruction_unit_test(0x05612c23, Opcode::SW, 22,2, 88); // sw x22,88(x2)
        create_instruction_unit_test(0x01b12e23, Opcode::SW, 27,2, 28); // sw x27,28(x2)
        create_instruction_unit_test(0x01052223, Opcode::SW, 16, 10, 4); // sw x16,4(x10)
        create_instruction_unit_test(0x02052403, Opcode::LW, 8, 10, 32); // lw x8,32(x10)
        create_instruction_unit_test(0x03452683, Opcode::LW, 13, 10, 52); // lw x13,52(x10)
        create_instruction_unit_test(0x0006a703, Opcode::LW, 14,13, 0); // lw x14,0(x13)
        create_instruction_unit_test(0x00001a37, Opcode::LUI,20,0x1, 0); // lui x20,0x1
        create_instruction_unit_test(0x800002b7, Opcode::LUI,5,0x80000, 0); // lui x5,0x80000
        create_instruction_unit_test(0x212120b7, Opcode::LUI,1,0x21212, 0); // lui x1,0x21212
        create_instruction_unit_test(0x00e78023, Opcode::SB, 14, 15,0); // SB x14,0(x15)
        create_instruction_unit_test(0x001101a3, Opcode::SB, 1,2, 3); // SB x1,3(x2)
        // TODO: do we want to support a negative offset?
        // create_instruction_unit_test(0xfee78fa3, Opcode::SB, 14, 15, -1); // SB x14,-1(x15)

        create_instruction_unit_test(0x7e7218e3, Opcode::BNE, 4,7, 0xff0);
        create_instruction_unit_test(0x5a231763, Opcode::BNE, 6,2,0x5ae);
        create_instruction_unit_test(0x0eb51fe3, Opcode::BNE, 10,11,0x8fe);

        create_instruction_unit_test(0x7e7268e3, Opcode::BLTU, 4,7, 0xff0);
        create_instruction_unit_test(0x5a236763, Opcode::BLTU, 6,2,0x5ae);
        create_instruction_unit_test(0x0eb56fe3, Opcode::BLTU, 10,11,0x8fe);

        create_instruction_unit_test(0x0020bf33, Opcode::SLTU, 30,1,2);
        create_instruction_unit_test(0x0020bf33, Opcode::SLTU, 30,1,2);
        create_instruction_unit_test(0x000030b3, Opcode::SLTU, 1,0,0);

        create_instruction_unit_test(0x0006c783, Opcode::LBU, 15,13, 0);
        create_instruction_unit_test(0x0006c703, Opcode::LBU, 14,13, 0);
        create_instruction_unit_test(0x0007c683, Opcode::LBU, 13,15, 0);

        // TODO: Do we want to support a negative offset?
        // create_instruction_unit_test(0xff867693,  Opcode::ANDI, 13,12,-8);
        create_instruction_unit_test(0x08077693,  Opcode::ANDI, 13,14,128);
        create_instruction_unit_test(0x04077693,  Opcode::ANDI, 13,14,64);

        // TODO: negative offset?
        // create_instruction_unit_test(0xfe209d23, Opcode::SH, 2, 1, -6); // sh x2,-6(x1)
        create_instruction_unit_test(0x00111223, Opcode::SH, 1, 2, 4); // sh x1,4(x2)
        create_instruction_unit_test(0x00111523, Opcode::SH, 1, 2, 10); // sh x1,10(x2)

        create_instruction_unit_test(0x25c000ef, Opcode::JAL, 1, 604, 0); // jal x1 604
        create_instruction_unit_test(0x72ff24ef, Opcode::JAL, 9, 0xf2f2e, 0); // jal x1 604
        create_instruction_unit_test(0x2f22f36f, Opcode::JAL, 6, 0x2f2f2, 0); // jal x1 604
    }
}
