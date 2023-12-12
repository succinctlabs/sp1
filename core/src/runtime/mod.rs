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
    pub fn r_type(&self) -> (usize, usize, usize) {
        (self.a as usize, self.b as usize, self.c as usize)
    }

    pub fn i_type(&self) -> (usize, usize, u32) {
        (self.a as usize, self.b as usize, self.c)
    }

    pub fn s_type(&self) -> (usize, usize, u32) {
        (self.a as usize, self.b as usize, self.c)
    }

    pub fn b_type(&self) -> (usize, usize, u32) {
        (self.a as usize, self.b as usize, self.c)
    }

    pub fn j_type(&self) -> (usize, u32) {
        (self.a as usize, self.b)
    }

    pub fn u_type(&self) -> (usize, u32) {
        (self.a as usize, self.b)
    }
}

pub struct Runtime {
    clk: u32,
    pc: u32,
    registers: [u32; 32],
    memory: BTreeMap<u32, u32>,
    code: Vec<Instruction>,
}

impl Runtime {
    pub fn new(code: Vec<Instruction>) -> Self {
        Self {
            clk: 0,
            pc: 0,
            registers: [0; 32],
            memory: BTreeMap::new(),
            code,
        }
    }

    pub fn fetch(&self) -> Instruction {
        let idx = (self.pc / 4) as usize;
        return self.code[idx];
    }

    pub fn execute(&mut self, instruction: Instruction) {
        match instruction.opcode {
            // R-type instructions.
            Opcode::ADD => {
                let (rd, rs1, rs2) = instruction.r_type();
                self.registers[rd] = self.registers[rs1].wrapping_add(self.registers[rs2]);
            }
            Opcode::SUB => {
                let (rd, rs1, rs2) = instruction.r_type();
                self.registers[rd] = self.registers[rs1].wrapping_sub(self.registers[rs2]);
            }
            Opcode::XOR => {
                let (rd, rs1, rs2) = instruction.r_type();
                self.registers[rd] = self.registers[rs1] ^ self.registers[rs2];
            }
            Opcode::OR => {
                let (rd, rs1, rs2) = instruction.r_type();
                self.registers[rd] = self.registers[rs1] | self.registers[rs2];
            }
            Opcode::AND => {
                let (rd, rs1, rs2) = instruction.r_type();
                self.registers[rd] = self.registers[rs1] & self.registers[rs2];
            }
            Opcode::SLL => {
                let (rd, rs1, rs2) = instruction.r_type();
                self.registers[rd] = self.registers[rs1] << self.registers[rs2];
            }
            Opcode::SRL => {
                let (rd, rs1, rs2) = instruction.r_type();
                self.registers[rd] = self.registers[rs1] >> self.registers[rs2];
            }
            Opcode::SRA => {
                let (rd, rs1, rs2) = instruction.r_type();
                self.registers[rd] = (self.registers[rs1] as i32 >> self.registers[rs2]) as u32;
            }
            Opcode::SLT => {
                let (rd, rs1, rs2) = instruction.r_type();
                self.registers[rd] = if (self.registers[rs1] as i32) < (self.registers[rs2] as i32)
                {
                    1
                } else {
                    0
                };
            }
            Opcode::SLTU => {
                let (rd, rs1, rs2) = instruction.r_type();
                self.registers[rd] = if self.registers[rs1] < self.registers[rs2] {
                    1
                } else {
                    0
                };
            }

            // I-type instructions.
            Opcode::ADDI => {
                let (rd, rs1, imm) = instruction.i_type();
                self.registers[rd] = self.registers[rs1].wrapping_add(imm);
            }
            Opcode::XORI => {
                let (rd, rs1, imm) = instruction.i_type();
                self.registers[rd] = self.registers[rs1] ^ imm;
            }
            Opcode::ORI => {
                let (rd, rs1, imm) = instruction.i_type();
                self.registers[rd] = self.registers[rs1] | imm;
            }
            Opcode::ANDI => {
                let (rd, rs1, imm) = instruction.i_type();
                self.registers[rd] = self.registers[rs1] & imm;
            }
            Opcode::SLLI => {
                let (rd, rs1, imm) = instruction.i_type();
                self.registers[rd] = self.registers[rs1] << imm;
            }
            Opcode::SRLI => {
                let (rd, rs1, imm) = instruction.i_type();
                self.registers[rd] = self.registers[rs1] >> imm;
            }
            Opcode::SRAI => {
                let (rd, rs1, imm) = instruction.i_type();
                self.registers[rd] = (self.registers[rs1] as i32 >> imm) as u32;
            }
            Opcode::SLTI => {
                let (rd, rs1, imm) = instruction.i_type();
                self.registers[rd] = if (self.registers[rs1] as i32) < (imm as i32) {
                    1
                } else {
                    0
                };
            }
            Opcode::SLTIU => {
                let (rd, rs1, imm) = instruction.i_type();
                self.registers[rd] = if self.registers[rs1] < imm { 1 } else { 0 };
            }
            Opcode::LB => {
                let (rd, rs1, imm) = instruction.i_type();
                let addr = self.registers[rs1].wrapping_add(imm);
                self.registers[rd] = (self.memory[&addr] as i8) as u32;
            }
            Opcode::LH => {
                let (rd, rs1, imm) = instruction.i_type();
                let addr = self.registers[rs1].wrapping_add(imm);
                self.registers[rd] = (self.memory[&addr] as i16) as u32;
            }
            Opcode::LW => {
                let (rd, rs1, imm) = instruction.i_type();
                let addr = self.registers[rs1].wrapping_add(imm);
                self.registers[rd] = self.memory[&addr];
            }
            Opcode::LBU => {
                let (rd, rs1, imm) = instruction.i_type();
                let addr = self.registers[rs1].wrapping_add(imm);
                self.registers[rd] = (self.memory[&addr] as u8) as u32;
            }
            Opcode::LHU => {
                let (rd, rs1, imm) = instruction.i_type();
                let addr = self.registers[rs1].wrapping_add(imm);
                self.registers[rd] = (self.memory[&addr] as u16) as u32;
            }

            // S-type instructions.
            Opcode::SB => {
                let (rs1, rs2, imm) = instruction.s_type();
                let addr = self.registers[rs1].wrapping_add(imm);
                self.memory.insert(addr, (self.registers[rs2] as u8) as u32);
            }
            Opcode::SH => {
                let (rs1, rs2, imm) = instruction.s_type();
                let addr = self.registers[rs1].wrapping_add(imm);
                self.memory
                    .insert(addr, (self.registers[rs2] as u16) as u32);
            }
            Opcode::SW => {
                let (rs1, rs2, imm) = instruction.s_type();
                let addr = self.registers[rs1].wrapping_add(imm);
                self.memory.insert(addr, self.registers[rs2]);
            }

            // B-type instructions.
            Opcode::BEQ => {
                let (rs1, rs2, imm) = instruction.b_type();
                if self.registers[rs1] == self.registers[rs2] {
                    self.pc = self.pc.wrapping_add(imm);
                }
            }
            Opcode::BNE => {
                let (rs1, rs2, imm) = instruction.b_type();
                if self.registers[rs1] != self.registers[rs2] {
                    self.pc = self.pc.wrapping_add(imm);
                }
            }
            Opcode::BLT => {
                let (rs1, rs2, imm) = instruction.b_type();
                if (self.registers[rs1] as i32) < (self.registers[rs2] as i32) {
                    self.pc = self.pc.wrapping_add(imm);
                }
            }
            Opcode::BGE => {
                let (rs1, rs2, imm) = instruction.b_type();
                if (self.registers[rs1] as i32) >= (self.registers[rs2] as i32) {
                    self.pc = self.pc.wrapping_add(imm);
                }
            }
            Opcode::BLTU => {
                let (rs1, rs2, imm) = instruction.b_type();
                if self.registers[rs1] < self.registers[rs2] {
                    self.pc = self.pc.wrapping_add(imm);
                }
            }
            Opcode::BGEU => {
                let (rs1, rs2, imm) = instruction.b_type();
                if self.registers[rs1] >= self.registers[rs2] {
                    self.pc = self.pc.wrapping_add(imm);
                }
            }

            // Jump instructions.
            Opcode::JAL => {
                let (rd, imm) = instruction.j_type();
                self.registers[rd] = self.pc + 4;
                self.pc = self.pc.wrapping_add(imm);
            }
            Opcode::JALR => {
                let (rd, rs1, imm) = instruction.i_type();
                self.registers[rd] = self.pc + 4;
                self.pc = self.registers[rs1].wrapping_add(imm);
            }

            // Upper immediate instructions.
            Opcode::LUI => {
                let (rd, imm) = instruction.u_type();
                self.registers[rd] = imm << 12;
            }
            Opcode::AUIPC => {
                let (rd, imm) = instruction.u_type();
                self.registers[rd] = self.pc.wrapping_add(imm << 12);
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
                self.registers[rd] = self.registers[rs1].wrapping_mul(self.registers[rs2]);
            }
            Opcode::MULH => {
                let (rd, rs1, rs2) = instruction.r_type();
                self.registers[rd] = ((self.registers[rs1] as i64)
                    .wrapping_mul(self.registers[rs2] as i64)
                    >> 32) as u32;
            }
            Opcode::MULSU => {
                let (rd, rs1, rs2) = instruction.r_type();
                self.registers[rd] = ((self.registers[rs1] as i64)
                    .wrapping_mul(self.registers[rs2] as i64)
                    >> 32) as u32;
            }
            Opcode::MULU => {
                let (rd, rs1, rs2) = instruction.r_type();
                self.registers[rd] = ((self.registers[rs1] as u64)
                    .wrapping_mul(self.registers[rs2] as u64)
                    >> 32) as u32;
            }
            Opcode::DIV => {
                let (rd, rs1, rs2) = instruction.r_type();
                self.registers[rd] =
                    (self.registers[rs1] as i32).wrapping_div(self.registers[rs2] as i32) as u32;
            }
            Opcode::DIVU => {
                let (rd, rs1, rs2) = instruction.r_type();
                self.registers[rd] = self.registers[rs1].wrapping_div(self.registers[rs2]);
            }
            Opcode::REM => {
                let (rd, rs1, rs2) = instruction.r_type();
                self.registers[rd] =
                    (self.registers[rs1] as i32).wrapping_rem(self.registers[rs2] as i32) as u32;
            }
            Opcode::REMU => {
                let (rd, rs1, rs2) = instruction.r_type();
                self.registers[rd] = self.registers[rs1].wrapping_rem(self.registers[rs2]);
            }
        }
    }

    pub fn run(&mut self) {
        // Set %x2 to the size of memory when the CPU is initialized.
        self.registers[Register::X2] = 1024 * 1024 * 8;

        // In each cycle, %x0 should be hardwired to 0.
        self.registers[Register::X0] = 0;

        while self.pc < (self.code.len() * 4) as u32 {
            let instruction = self.fetch();
            self.pc = self.pc + 4;
            self.execute(instruction);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Runtime;

    use super::{Instruction, Opcode};

    #[test]
    fn add() {
        // main:
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     add x31, x30, x29
        let code = vec![
            Instruction {
                opcode: Opcode::ADDI,
                a: 29,
                b: 0,
                c: 5,
            },
            Instruction {
                opcode: Opcode::ADDI,
                a: 30,
                b: 0,
                c: 37,
            },
            Instruction {
                opcode: Opcode::ADD,
                a: 31,
                b: 30,
                c: 29,
            },
        ];
        let mut runtime = Runtime::new(code);
        runtime.run();
        println!("{:?}", runtime.registers);
    }
}
