use super::{AssemblyCode, BasicBlock};
use alloc::collections::BTreeMap;
use alloc::string::String;

use p3_field::PrimeField32;

use crate::asm::AsmInstruction;
use crate::builder::Builder;

#[derive(Debug, Clone)]
pub struct AsmBuilder<F> {
    fp_offset: i32,

    current_block: usize,

    pub basic_blocks: BTreeMap<usize, BasicBlock<F>>,

    block_order: Vec<usize>,

    function_labels: BTreeMap<String, F>,
}

impl<F: PrimeField32> AsmBuilder<F> {
    pub fn new() -> Self {
        Self {
            fp_offset: -4,
            current_block: 0,
            basic_blocks: BTreeMap::from([(0, BasicBlock::new())]),
            function_labels: BTreeMap::new(),
            block_order: vec![0],
        }
    }

    pub fn code(mut self) -> AssemblyCode<F> {
        let labels = self
            .function_labels
            .into_iter()
            .map(|(k, v)| (v, k))
            .collect();
        let blocks = self
            .block_order
            .into_iter()
            .map(|i| {
                (
                    F::from_canonical_usize(i),
                    self.basic_blocks.remove(&i).unwrap(),
                )
            })
            .collect();
        AssemblyCode::new(blocks, labels)
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
        let label = self.basic_blocks.len();
        let idx = self.current_block + 1;
        self.basic_blocks.insert(label, BasicBlock::new());
        self.current_block = label;

        self.block_order.insert(idx, label);
    }

    fn block_label(&mut self) -> F {
        F::from_canonical_usize(self.current_block)
    }

    fn next_label(&mut self) -> F {
        F::from_canonical_usize(self.basic_blocks.len())
    }

    fn set_current_block(&mut self, label: Self::F) {
        self.current_block = label.as_canonical_u32() as usize;
    }

    // fn push_to_block(&mut self, block_label: Self::F, instruction: AsmInstruction<Self::F>) {
    //     self.basic_blocks
    //         .get_mut(block_label.as_canonical_u32() as usize)
    //         .unwrap_or_else(|| panic!("Missing block at label: {:?}", block_label))
    //         .push(instruction);
    // }

    fn push(&mut self, instruction: AsmInstruction<F>) {
        self.basic_blocks
            .get_mut(&self.current_block)
            .expect("Missing current block")
            .push(instruction);
    }
}

impl<F: PrimeField32> Default for AsmBuilder<F> {
    fn default() -> Self {
        Self::new()
    }
}
