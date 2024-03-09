use super::AsmInstruction;
use alloc::format;
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::fmt;
use core::fmt::Display;
use p3_field::PrimeField32;
use sp1_recursion_core::runtime::Program;

#[derive(Debug, Clone, Default)]
pub struct BasicBlock<F> {
    instructions: Vec<AsmInstruction<F>>,
}

#[derive(Debug, Clone)]
pub struct AssemblyCode<F> {
    blocks: Vec<(F, BasicBlock<F>)>,
    labels: BTreeMap<F, String>,
}

impl<F: PrimeField32> BasicBlock<F> {
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, instruction: AsmInstruction<F>) {
        self.instructions.push(instruction);
    }
}

impl<F: PrimeField32> AssemblyCode<F> {
    pub fn new(blocks: Vec<(F, BasicBlock<F>)>, labels: BTreeMap<F, String>) -> Self {
        Self { blocks, labels }
    }

    pub fn machine_code(self) -> Program<F> {
        let blocks = self.blocks;

        // Make a first pass to collect all the pc rows corresponding to the labels.
        let mut label_to_pc = BTreeMap::new();
        let mut pc = 0;
        for (label, block) in blocks.iter() {
            label_to_pc.insert(*label, pc);
            pc += block.instructions.len();
        }

        // Make the second pass to convert the assembly code to machine code.
        let mut machine_code = Vec::new();
        let mut pc = 0;
        for (_, block) in blocks {
            for instruction in block.instructions {
                machine_code.push(instruction.to_machine(pc, &label_to_pc));
                pc += 1;
            }
        }

        Program {
            instructions: machine_code,
        }
    }
}

impl<F: PrimeField32> Display for AssemblyCode<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (label, block) in self.blocks.iter() {
            writeln!(
                f,
                "{}:",
                self.labels.get(label).unwrap_or(&format!(".L{}", label))
            )?;
            for instruction in &block.instructions {
                write!(f, "        ")?;
                instruction.fmt(&self.labels, f)?;
                writeln!(f)?;
            }
        }
        Ok(())
    }
}
