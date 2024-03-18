use super::AsmInstruction;
use alloc::format;
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::fmt;
use core::fmt::Display;
use p3_field::{ExtensionField, PrimeField32};
use sp1_recursion_core::runtime::Program;

#[derive(Debug, Clone, Default)]
pub struct BasicBlock<F, EF>(Vec<AsmInstruction<F, EF>>);

#[derive(Debug, Clone)]
pub struct AssemblyCode<F, EF> {
    blocks: Vec<BasicBlock<F, EF>>,
    labels: BTreeMap<F, String>,
}

impl<F: PrimeField32, EF: ExtensionField<F>> BasicBlock<F, EF> {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn push(&mut self, instruction: AsmInstruction<F, EF>) {
        self.0.push(instruction);
    }
}

impl<F: PrimeField32, EF: ExtensionField<F>> AssemblyCode<F, EF> {
    pub fn new(blocks: Vec<BasicBlock<F, EF>>, labels: BTreeMap<F, String>) -> Self {
        Self { blocks, labels }
    }

    pub fn machine_code(self) -> Program<F> {
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

        Program {
            instructions: machine_code,
        }
    }
}

impl<F: PrimeField32, EF: ExtensionField<F>> Display for AssemblyCode<F, EF> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, block) in self.blocks.iter().enumerate() {
            writeln!(
                f,
                "{}:",
                self.labels
                    .get(&F::from_canonical_u32(i as u32))
                    .unwrap_or(&format!(".L{}", i))
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
