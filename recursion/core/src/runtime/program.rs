use super::Instruction;
use backtrace::Backtrace;
use p3_field::Field;
use sp1_core::air::MachineProgram;

#[derive(Debug, Clone, Default)]
pub struct RecursionProgram<F> {
    pub instructions: Vec<Instruction<F>>,
    pub traces: Vec<Option<Backtrace>>,
}

impl<F: Field> MachineProgram<F> for RecursionProgram<F> {
    fn pc_start(&self) -> F {
        F::zero()
    }
}
