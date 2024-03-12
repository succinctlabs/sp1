use super::{AssemblyCode, BasicBlock};
use crate::ir::Int;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use p3_field::PrimeField32;
use sp1_recursion_core::runtime::Program;

use crate::asm::AsmInstruction;
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

    pub fn compile(self) -> Program<F> {
        let code = self.code();
        code.machine_code()
    }
}

impl<F: PrimeField32> Builder for AsmBuilder<F> {
    type F = F;

    fn get_mem(&mut self, size: usize) -> i32 {
        let offset = self.fp_offset;
        self.fp_offset -= size as i32;
        offset
    }

    fn alloc(&mut self, _size: Int) -> Int {
        todo!()
    }

    fn basic_block(&mut self) {
        self.basic_blocks.push(BasicBlock::new());
    }

    fn block_label(&mut self) -> F {
        F::from_canonical_usize(self.basic_blocks.len() - 1)
    }

    fn get_block_mut(&mut self, label: Self::F) -> &mut BasicBlock<Self::F> {
        &mut self.basic_blocks[label.as_canonical_u32() as usize]
    }

    fn push_to_block(&mut self, block_label: Self::F, instruction: AsmInstruction<Self::F>) {
        self.basic_blocks
            .get_mut(block_label.as_canonical_u32() as usize)
            .unwrap_or_else(|| panic!("Missing block at label: {:?}", block_label))
            .push(instruction);
    }

    fn push(&mut self, instruction: AsmInstruction<F>) {
        self.basic_blocks.last_mut().unwrap().push(instruction);
    }
}

impl<F: PrimeField32> Default for AsmBuilder<F> {
    fn default() -> Self {
        Self::new()
    }
}
