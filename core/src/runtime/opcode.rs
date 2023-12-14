use std::fmt::{Display, Formatter};


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
    MULHU = 41,
    MULHSU = 42,
    MULU = 43,
    DIV = 44,
    DIVU = 45,
    REM = 46,
    REMU = 47,

    UNIMP = 48,
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
            Opcode::MULHSU => write!(f, "mulhsu"),
            Opcode::MULHU => write!(f, "mulhu"),
            Opcode::MULU => write!(f, "mulu"),
            Opcode::DIV => write!(f, "div"),
            Opcode::DIVU => write!(f, "divu"),
            Opcode::REM => write!(f, "rem"),
            Opcode::REMU => write!(f, "remu"),

            Opcode::UNIMP => write!(f, "unimp"),
        }
    }
}
