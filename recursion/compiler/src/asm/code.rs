use super::Instruction;
use alloc::format;
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::fmt;
use core::fmt::Display;
use p3_field::PrimeField32;

#[derive(Debug, Clone, Default)]
pub struct BasicBlock<F>(Vec<Instruction<F>>);

#[derive(Debug, Clone)]
pub struct AssemblyCode<F> {
    blocks: Vec<BasicBlock<F>>,
    labels: BTreeMap<F, String>,
}

impl<F: PrimeField32> BasicBlock<F> {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn push(&mut self, instruction: Instruction<F>) {
        self.0.push(instruction);
    }
}

impl<F: PrimeField32> AssemblyCode<F> {
    pub fn new(blocks: Vec<BasicBlock<F>>, labels: BTreeMap<F, String>) -> Self {
        Self { blocks, labels }
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
