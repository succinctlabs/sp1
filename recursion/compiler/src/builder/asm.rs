use std::fmt::Display;

use p3_field::PrimeField32;

use super::Builder;
use crate::asm::Instruction;

#[derive(Debug, Clone, Default)]
pub struct BasicBlock<F>(Vec<Instruction<F>>);

#[derive(Debug, Clone, Default)]
pub struct AsmBuilder<F> {
    fp_offset: i32,

    pub basic_blocks: Vec<BasicBlock<F>>,
}

impl<F: PrimeField32> AsmBuilder<F> {
    pub fn new() -> Self {
        Self {
            fp_offset: -4,
            basic_blocks: vec![BasicBlock::new()],
        }
    }
}

impl<F: PrimeField32> Builder for AsmBuilder<F> {
    type F = F;

    fn get_mem(&mut self, size: usize) -> i32 {
        let offset = self.fp_offset;
        self.fp_offset -= size as i32;
        offset
    }

    fn basic_block(&mut self) {
        self.basic_blocks.push(BasicBlock::new());
    }

    fn push(&mut self, instruction: Instruction<F>) {
        self.basic_blocks.last_mut().unwrap().push(instruction);
    }
}

impl<F: PrimeField32> BasicBlock<F> {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    fn push(&mut self, instruction: Instruction<F>) {
        self.0.push(instruction);
    }
}

impl<F: Display> Display for BasicBlock<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for instruction in &self.0 {
            writeln!(f, "        {}", instruction)?;
        }
        Ok(())
    }
}
