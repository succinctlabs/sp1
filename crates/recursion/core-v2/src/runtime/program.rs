use backtrace::Backtrace;
use p3_field::Field;
use serde::{Deserialize, Serialize};
use shape::RecursionShape;
use sp1_stark::air::{MachineAir, MachineProgram};

use crate::*;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecursionProgram<F> {
    pub instructions: Vec<Instruction<F>>,
    pub total_memory: usize,
    #[serde(skip)]
    pub traces: Vec<Option<Backtrace>>,
    pub shape: Option<RecursionShape>,
}

impl<F: Field> MachineProgram<F> for RecursionProgram<F> {
    fn pc_start(&self) -> F {
        F::zero()
    }
}

impl<F: Field> RecursionProgram<F> {
    #[inline]
    pub fn fixed_log2_rows<A: MachineAir<F>>(&self, air: &A) -> Option<usize> {
        self.shape
            .as_ref()
            .map(|shape| {
                shape
                    .inner
                    .get(&air.name())
                    .unwrap_or_else(|| panic!("Chip {} not found in specified shape", air.name()))
            })
            .copied()
    }
}
