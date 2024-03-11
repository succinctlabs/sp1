use super::BasicBlock;
use super::Felt;
use super::Int;
use super::VmBuilder;
use crate::syn::BaseBuilder;
use p3_field::AbstractField;

use super::AsmInstruction;

/// A builder for a for loop.
///
/// Starting with end < start will lead to undefined behavior!
pub struct ForVmBuilder<'a, B: VmBuilder> {
    pub(crate) builder: &'a mut B,
    pub(crate) start: Felt<B::F>,
    pub(crate) end: Felt<B::F>,
    pub(crate) loop_var: Felt<B::F>,
}

impl<'a, B: VmBuilder> BaseBuilder for ForVmBuilder<'a, B> {}

impl<'a, B: VmBuilder> VmBuilder for ForVmBuilder<'a, B> {
    type F = B::F;
    fn get_mem(&mut self, size: usize) -> i32 {
        self.builder.get_mem(size)
    }

    fn alloc(&mut self, size: Int) -> Int {
        self.builder.alloc(size)
    }

    fn push(&mut self, instruction: AsmInstruction<B::F>) {
        self.builder.push(instruction);
    }

    fn get_block_mut(&mut self, label: Self::F) -> &mut BasicBlock<Self::F> {
        self.builder.get_block_mut(label)
    }

    fn basic_block(&mut self) {
        self.builder.basic_block();
    }

    fn block_label(&mut self) -> B::F {
        self.builder.block_label()
    }
}

impl<'a, B: VmBuilder> ForVmBuilder<'a, B> {
    pub fn for_each<Func>(&mut self, f: Func)
    where
        Func: FnOnce(Felt<B::F>, &mut Self),
    {
        // The function block structure:
        // - Setting the loop range
        // - Executing the loop body and incrementing the loop variable
        // - the loop condition
        let loop_var = self.loop_var;
        // Set the loop variable to the start of the range.
        self.assign(loop_var, self.start);
        // Save the label of the for loop call
        let loop_call_label = self.block_label();
        // A basic block for the loop body
        self.basic_block();
        // Save the loop body label for the loop condition.
        let loop_label = self.block_label();
        // The loop body.
        f(loop_var, self);
        self.assign(loop_var, loop_var + B::F::one());
        // Add a basic block for the loop condition.
        self.basic_block();
        // Jump to loop body if the loop condition still holds.
        let instr = AsmInstruction::BNE(loop_label, loop_var.0, self.end.0);
        self.push(instr);
        // Add a jump instruction to the loop condition in the following block
        let label = self.block_label();
        let instr = AsmInstruction::j(label, self);
        self.push_to_block(loop_call_label, instr);
    }
}
