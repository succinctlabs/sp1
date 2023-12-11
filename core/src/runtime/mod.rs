use std::{
    collections::BTreeMap,
    fmt::{Display, Formatter},
};

/// An opcode specifies which operation to execute.
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

            Opcode::ADDI => write!(f, "addi"),
            Opcode::XORI => write!(f, "xori"),
            Opcode::ORI => write!(f, "ori"),
            Opcode::ANDI => write!(f, "andi"),
            Opcode::SLLI => write!(f, "slli"),
            Opcode::SRLI => write!(f, "srli"),
            Opcode::SRAI => write!(f, "srai"),
            Opcode::SLTI => write!(f, "slti"),
            Opcode::SLTIU => write!(f, "sltiu"),

            Opcode::LB => write!(f, "lb"),
            Opcode::LH => write!(f, "lh"),
            Opcode::LW => write!(f, "lw"),
            Opcode::LBU => write!(f, "lbu"),
            Opcode::LHU => write!(f, "lhu"),

            Opcode::SB => write!(f, "sb"),
            Opcode::SH => write!(f, "sh"),
            Opcode::SW => write!(f, "sw"),

            Opcode::BEQ => write!(f, "beq"),
            Opcode::BNE => write!(f, "bne"),
            Opcode::BLT => write!(f, "blt"),
            Opcode::BGE => write!(f, "bge"),
            Opcode::BLTU => write!(f, "bltu"),
            Opcode::BGEU => write!(f, "bgeu"),

            Opcode::JAL => write!(f, "jal"),
            Opcode::JALR => write!(f, "jalr"),
            Opcode::LUI => write!(f, "lui"),
            Opcode::AUIPC => write!(f, "auipc"),

            Opcode::ECALL => write!(f, "ecall"),
            Opcode::EBREAK => write!(f, "ebreak"),

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
pub enum RegisterOrImmediate {
    Register(Register),
    Immediate(i32),
}

/// An instruction specifies an operation to execute and the operands.
pub struct Instruction {
    opcode: Opcode,
    a: Register,
    b: Register,
    c: RegisterOrImmediate,
}

pub struct Runtime {
    clk: u32,
    registers: [u32; 32],
    memory: BTreeMap<u32, u32>,
}

impl Runtime {
    pub fn new() -> Self {
        Self {
            clk: 0,
            registers: [0; 32],
            memory: BTreeMap::new(),
        }
    }

    // Option 1: ELF -> SuccinctELF -> Runtime

    // fn cpu_event(&mut self, instruction: &Instruction<i32>) {
    //     self.segment.cpu_events.push(CpuEvent {
    //         clk: self.clk,
    //         fp: self.fp,
    //         pc: self.pc,
    //         instruction: *instruction,
    //     });
    // }

    // fn read_word(&mut self, addr: usize) -> i32 {
    //     i32::from_le_bytes(
    //         self.memory[addr as usize..addr as usize + 4]
    //             .try_into()
    //             .unwrap(),
    //     )
    // }

    // fn write_word(&mut self, addr: usize, value: i32) {
    //     // TODO: can you write to uninitialized memory?
    //     self.memory[addr as usize..addr as usize + 4].copy_from_slice(&value.to_le_bytes());
    // }

    // fn alu_op(&mut self, op: Opcode, addr_d: usize, addr_1: usize, addr_2: usize) -> i32 {
    //     let v1 = self.read_word(addr_1);
    //     let v2 = self.read_word(addr_2);
    //     let result = match op {
    //         Opcode::ADD => v1 + v2,
    //         Opcode::AND => v1 | v2,
    //         Opcode::SLL => v1 << v2,
    //         _ => panic!("Invalid ALU opcode {}", op),
    //     };
    //     self.write_word(addr_d, result);
    //     self.segment.alu_events.push(AluEvent {
    //         clk: self.clk,
    //         opcode: op as u32,
    //         addr_d,
    //         addr_1,
    //         addr_2,
    //         v_d: result,
    //         v_1: v1,
    //         v_2: v2,
    //     });
    //     result
    // }

    // fn imm(&mut self, addr: usize, imm: i32) {
    //     self.write_word(addr, imm);
    // }

    // pub fn run(&mut self) -> Result<()> {
    //     // Iterate through the program, executing each instruction.
    //     let current_instruction = self.program.get_instruction(self.pc);
    //     let operands = current_instruction.operands.0;
    //     self.cpu_event(&current_instruction);

    //     match current_instruction.opcode {
    //         Opcode::ADD | Opcode::SUB | Opcode::XOR | Opcode::AND => {
    //             // Calculate address of each operand.
    //             let addr_d = self.fp + operands[0];
    //             let addr_1 = self.fp + operands[1];
    //             let addr_2 = self.fp + operands[2];

    //             self.alu_op(
    //                 current_instruction.opcode,
    //                 addr_d as usize,
    //                 addr_1 as usize,
    //                 addr_2 as usize,
    //             );
    //             self.pc += 1;
    //         }
    //         Opcode::IMM => {
    //             // Calculate address.
    //             let addr = (self.fp + operands[0]) as u32;
    //             let imm = operands[1];
    //             self.imm(addr as usize, imm);
    //         }
    //         _ => panic!("Invalid opcode {}", current_instruction.opcode),
    //     }

    //     self.clk += 1;
    //     Ok(())
    // }
}
