use alloc::collections::BTreeMap;
use alloc::format;
use backtrace::Backtrace;
use core::fmt;
use core::fmt::Display;

use p3_field::{ExtensionField, PrimeField32};
use sp1_recursion_core::runtime::RecursionProgram;

use super::AsmInstruction;

/// A basic block of assembly instructions.
#[derive(Debug, Clone, Default)]
pub struct BasicBlock<F, EF>(
    pub(crate) Vec<AsmInstruction<F, EF>>,
    pub(crate) Vec<Option<Backtrace>>,
);

impl<F: PrimeField32, EF: ExtensionField<F>> BasicBlock<F, EF> {
    /// Creates a new basic block.
    pub fn new() -> Self {
        Self(Vec::new(), Vec::new())
    }

    /// Pushes an instruction to a basic block.
    pub(crate) fn push(
        &mut self,
        instruction: AsmInstruction<F, EF>,
        backtrace: Option<Backtrace>,
    ) {
        self.0.push(instruction);
        self.1.push(backtrace);
    }
}

/// Assembly code for a program.
#[derive(Debug, Clone)]
pub struct AssemblyCode<F, EF> {
    blocks: Vec<BasicBlock<F, EF>>,
    labels: BTreeMap<F, String>,
}

impl<F: PrimeField32, EF: ExtensionField<F>> AssemblyCode<F, EF> {
    /// Creates a new assembly code.
    pub fn new(blocks: Vec<BasicBlock<F, EF>>, labels: BTreeMap<F, String>) -> Self {
        Self { blocks, labels }
    }

    pub fn size(&self) -> usize {
        self.blocks.iter().map(|block| block.0.len()).sum()
    }

    /// Convert the assembly code to a program.
    pub fn machine_code(self) -> RecursionProgram<F> {
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
        let mut traces = Vec::new();
        let mut pc = 0;
        for block in blocks {
            for (instruction, trace) in block.0.into_iter().zip(block.1) {
                machine_code.push(instruction.to_machine(pc, &label_to_pc));
                traces.push(trace);
                pc += 1;
            }
        }

        RecursionProgram {
            instructions: machine_code,
            traces,
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
