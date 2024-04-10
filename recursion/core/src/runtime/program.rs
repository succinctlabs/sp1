use super::Instruction;

#[derive(Debug, Clone, Default)]
pub struct RecursionProgram<F> {
    pub instructions: Vec<Instruction<F>>,
}
