use core::fmt;

#[derive(Debug, Clone, Copy)]
pub enum Instruction<F> {
    /// Load work (src, dst) : load a value from the address stored at dest(fp) into src(fp).
    LW(i32, i32),
    /// Store word (src, dst) : store a value from src(fp) into the address stored at dest(fp).
    SW(i32, i32),
    // Get immediate (dst, value) : load a value into the dest(fp).
    IMM(i32, F),
    /// Add
    ADD(i32, i32, i32),
    /// Add immediate
    ADDI(i32, i32, F),
    /// Subtract
    SUB(i32, i32, i32),
    /// Multiply
    MUL(i32, i32, i32),
    /// Divide
    DIV(i32, i32, i32),
    /// Jump
    JUMP(i32),
}

impl<F: fmt::Display> fmt::Display for Instruction<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Instruction::LW(dst, src) => write!(f, "lw ({})fp, ({})fp", dst, src),
            Instruction::SW(dst, src) => write!(f, "sw ({})fp, ({})fp", dst, src),
            Instruction::IMM(dst, value) => write!(f, "imm ({})fp, {}", dst, value),
            Instruction::ADD(dst, lhs, rhs) => {
                write!(f, "add ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            Instruction::ADDI(dst, lhs, rhs) => write!(f, "addi ({})fp, ({})fp, {}", dst, lhs, rhs),
            Instruction::SUB(dst, lhs, rhs) => {
                write!(f, "sub ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            Instruction::MUL(dst, lhs, rhs) => {
                write!(f, "mul ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            Instruction::DIV(dst, lhs, rhs) => {
                write!(f, "div ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            Instruction::JUMP(label) => write!(f, "jump {}", label),
        }
    }
}
