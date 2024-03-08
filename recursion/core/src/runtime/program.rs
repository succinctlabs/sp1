use super::Instruction;

#[derive(Debug, Clone)]
pub struct Program<F> {
    /// The instructions of the program.
    pub instructions: Vec<Instruction<F>>,
}
