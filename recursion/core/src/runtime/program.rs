use super::Instruction;
use backtrace::Backtrace;

#[derive(Debug, Clone, Default)]
pub struct RecursionProgram<F> {
    pub instructions: Vec<Instruction<F>>,
    pub traces: Vec<Option<Backtrace>>,
}
