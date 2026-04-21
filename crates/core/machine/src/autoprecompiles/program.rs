use std::sync::Arc;

use crate::autoprecompiles::instruction::Sp1Instruction;
use powdr_autoprecompiles::blocks::{PcStep, Program};

#[derive(Default)]
pub struct Sp1Program(Arc<sp1_core_executor::Program>);

impl PcStep for Sp1Instruction {
    fn pc_step() -> u32 {
        // See [Program::fetch]
        4
    }
}

impl Program<Sp1Instruction> for Sp1Program {
    fn base_pc(&self) -> u64 {
        self.0.pc_base
    }

    fn instructions(&self) -> Box<dyn Iterator<Item = Sp1Instruction> + '_> {
        Box::new(self.0.instructions.iter().cloned().map(Sp1Instruction))
    }

    fn length(&self) -> u32 {
        self.0.instructions.len() as u32
    }
}

impl From<Arc<sp1_core_executor::Program>> for Sp1Program {
    fn from(inner: Arc<sp1_core_executor::Program>) -> Self {
        Sp1Program(inner)
    }
}
