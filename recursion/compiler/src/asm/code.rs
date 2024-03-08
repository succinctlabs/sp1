use super::AsmInstruction;
use alloc::format;
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::fmt;
use core::fmt::Display;
use p3_field::PrimeField32;
use sp1_recursion_core::runtime::Instruction;

#[derive(Debug, Clone, Default)]
pub struct BasicBlock<F>(Vec<AsmInstruction<F>>);

#[derive(Debug, Clone)]
pub struct AssemblyCode<F> {
    blocks: Vec<BasicBlock<F>>,
    labels: BTreeMap<F, String>,
}

impl<F: PrimeField32> BasicBlock<F> {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn push(&mut self, instruction: AsmInstruction<F>) {
        self.0.push(instruction);
    }
}

impl<F: PrimeField32> AssemblyCode<F> {
    pub fn new(blocks: Vec<BasicBlock<F>>, labels: BTreeMap<F, String>) -> Self {
        Self { blocks, labels }
    }

    pub fn machine_code(self) -> Vec<Instruction<F>> {
        let blocks = self.blocks;

        // Make a first pass to collect all the pc rows corresponding to the labels.
        let mut label_to_pc = BTreeMap::new();
        let mut pc = 0;
        for (i, block) in blocks.iter().enumerate() {
            label_to_pc.insert(F::from_canonical_usize(i), pc);
            pc += block.0.len();
        }

        // Make the second pass to convert the assembly code to machine code.
        let mut machine_code = Vec::new();
        let mut pc = 0;
        for block in blocks {
            for instruction in block.0 {
                machine_code.push(instruction.to_machine(pc, &label_to_pc));
                pc += 1;
            }
        }

        machine_code
    }
}

impl<F: PrimeField32> Display for AssemblyCode<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, block) in self.blocks.iter().enumerate() {
            writeln!(
                f,
                "{}:",
                self.labels
                    .get(&F::from_canonical_u32(i as u32))
                    .unwrap_or(&format!(".LBB_{}", i))
            )?;
            for instruction in &block.0 {
                write!(f, "        ")?;
                instruction.fmt(&self.labels, f)?;
                writeln!(f)?;
            }
        }
        Ok(())
    }
}
