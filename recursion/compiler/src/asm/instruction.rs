#[derive(Debug, Clone, Copy)]
pub enum Instruction {
    /// Load word
    LW(usize, usize),
    /// Store word
    SW(usize, usize),
    /// Add
    ADD(usize, usize, usize),
    /// Subtract
    SUB(usize, usize, usize),
    /// Multiply
    MUL(usize, usize, usize),
    /// Divide
    DIV(usize, usize, usize),
    /// Jump
    JUMP(usize),
}
