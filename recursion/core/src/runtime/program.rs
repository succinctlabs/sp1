use super::Instruction;
use backtrace::Backtrace;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecursionProgram<F> {
    pub instructions: Vec<Instruction<F>>,
    #[serde(skip)]
    pub traces: Vec<Option<Backtrace>>,
}
