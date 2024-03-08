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
    /// Subtract immediate
    SUBI(i32, i32, F),
    /// Subtract immediate and negate, dst = -lhs + rhs
    SUBIN(i32, i32, F),
    /// Multiply
    MUL(i32, i32, i32),
    /// Multiply immediate
    MULI(i32, i32, F),
    /// Divide
    DIV(i32, i32, i32),
    /// Divide immediate
    DIVI(i32, i32, F),
    /// Divide immediate and invert (dst = rhs / lhs)
    DIVIN(i32, i32, F),
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
            Instruction::SUBI(dst, lhs, rhs) => write!(f, "subi ({})fp, ({})fp, {}", dst, lhs, rhs),
            Instruction::SUBIN(dst, lhs, rhs) => {
                write!(f, "subin ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            Instruction::MUL(dst, lhs, rhs) => {
                write!(f, "mul ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            Instruction::MULI(dst, lhs, rhs) => write!(f, "muli ({})fp, ({})fp, {}", dst, lhs, rhs),
            Instruction::DIV(dst, lhs, rhs) => {
                write!(f, "div ({})fp, ({})fp, ({})fp", dst, lhs, rhs)
            }
            Instruction::DIVI(dst, lhs, rhs) => write!(f, "divi ({})fp, ({})fp, {}", dst, lhs, rhs),
            Instruction::DIVIN(dst, lhs, rhs) => {
                write!(f, "divin ({})fp, ({})fp, {}", dst, lhs, rhs)
            }
            Instruction::JUMP(label) => write!(f, "jump {}", label),
        }
    }
}
