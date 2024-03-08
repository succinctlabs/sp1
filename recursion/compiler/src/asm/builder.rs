use super::{AssemblyCode, BasicBlock};
use alloc::collections::BTreeMap;

use p3_field::PrimeField32;

use crate::asm::Instruction;
use crate::builder::Builder;

#[derive(Debug, Clone)]
pub struct AsmBuilder<F> {
    fp_offset: i32,

    pub basic_blocks: Vec<BasicBlock<F>>,

    function_labels: BTreeMap<String, F>,
}

impl<F: PrimeField32> AsmBuilder<F> {
    pub fn new() -> Self {
        Self {
            fp_offset: -4,
            basic_blocks: vec![BasicBlock::new()],
            function_labels: BTreeMap::new(),
        }
    }

    pub fn code(self) -> AssemblyCode<F> {
        let labels = self
            .function_labels
            .into_iter()
            .map(|(k, v)| (v, k))
            .collect();
        AssemblyCode::new(self.basic_blocks, labels)
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

    fn block_label(&mut self) -> F {
        F::from_canonical_usize(self.basic_blocks.len() - 1)
    }

    fn push(&mut self, instruction: Instruction<F>) {
        self.basic_blocks.last_mut().unwrap().push(instruction);
    }
}

impl<F: PrimeField32> Default for AsmBuilder<F> {
    fn default() -> Self {
        Self::new()
    }
}
