use backtrace::Backtrace;
use p3_field::Field;
use serde::{Deserialize, Serialize};
use sp1_stark::air::MachineProgram;

use crate::*;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecursionProgram<F> {
    pub instructions: Vec<Instruction<F>>,
    pub total_memory: usize,
    #[serde(skip)]
    pub traces: Vec<Option<Backtrace>>,
}

impl<F: Field> MachineProgram<F> for RecursionProgram<F> {
    fn pc_start(&self) -> F {
        F::zero()
    }
}
