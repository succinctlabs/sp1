use core::fmt;

use powdr_autoprecompiles::blocks::Instruction;
use serde::{Deserialize, Serialize};
use slop_algebra::AbstractField;
use sp1_primitives::SP1Field;

use crate::program::instruction::InstructionCols;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Sp1Instruction(pub sp1_core_executor::Instruction);

impl From<sp1_core_executor::Instruction> for Sp1Instruction {
    fn from(instr: sp1_core_executor::Instruction) -> Self {
        Self(instr)
    }
}

impl fmt::Display for Sp1Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl Instruction<SP1Field> for Sp1Instruction {
    fn pc_lookup_row(&self, pc: u64) -> Vec<SP1Field> {
        // The PC lookup row has the following structure:
        // [pc_0, pc_1, pc_2, ...instruction_cols]

        // The PC is represented as three 16-bit limbs, in little-endian order.
        let pc_limbs = vec![
            SP1Field::from_canonical_u64(pc & 0xFFFF),
            SP1Field::from_canonical_u64((pc >> 16) & 0xFFFF),
            SP1Field::from_canonical_u64((pc >> 32) & 0xFFFF),
        ];

        let mut instruction_cols = InstructionCols::<SP1Field>::default();
        instruction_cols.populate(&self.0);

        pc_limbs.into_iter().chain(instruction_cols).collect()
    }
}
