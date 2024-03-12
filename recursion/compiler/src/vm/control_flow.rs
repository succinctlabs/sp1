use super::BasicBlock;
use super::VmBuilder;
use crate::syn::BaseBuilder;
use crate::syn::Builder;
use crate::syn::Condition;
use crate::syn::ConstantConditionBuilder;
use crate::syn::IfBuilder;
use crate::vm::Int;

use crate::vm::AsmInstruction;

use crate::prelude::Symbolic;
use crate::prelude::SymbolicLogic;

use p3_field::AbstractField;

impl<B: VmBuilder> Condition<B> for SymbolicLogic {
    type IfBuilder<'a> = IfBoolBuilder<'a, B>
        where
        B: 'a;

    fn if_condition(self, builder: &mut B) -> Self::IfBuilder<'_> {
        IfBoolBuilder {
            builder,
            expr: self,
            is_true: true,
        }
    }
}

pub struct IfBoolBuilder<'a, B> {
    pub(crate) builder: &'a mut B,
    pub(crate) expr: SymbolicLogic,
    pub(crate) is_true: bool,
}

pub struct IfFeltBuilder<'a, B: VmBuilder> {
    pub(crate) builder: &'a mut B,
    pub(crate) lhs: Symbolic<B::F>,
    pub(crate) rhs: Symbolic<B::F>,
    pub(crate) is_eq: bool,
}

impl<'a, B: BaseBuilder> BaseBuilder for IfBoolBuilder<'a, B> {}

impl<'a, B: VmBuilder> VmBuilder for IfBoolBuilder<'a, B> {
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

impl<'a, B: VmBuilder> IfBuilder for IfBoolBuilder<'a, B> {
    fn then(self, f: impl FnOnce(&mut Self)) {
        self.then(f)
    }

    fn then_or_else(self, then_f: impl FnOnce(&mut Self), else_f: impl FnOnce(&mut Self)) {
        self.then_or_else(then_f, else_f)
    }
}

impl<'a, B: VmBuilder> IfBuilder for IfFeltBuilder<'a, B> {
    fn then(self, f: impl FnOnce(&mut Self)) {
        self.then(f)
    }

    fn then_or_else(self, then_f: impl FnOnce(&mut Self), else_f: impl FnOnce(&mut Self)) {
        self.then_or_else(then_f, else_f)
    }
}

impl<'a, B: VmBuilder> IfBoolBuilder<'a, B> {
    pub fn then(mut self, f: impl FnOnce(&mut Self)) {
        let after_if_block = self.block_label() + B::F::two();
        self.branch(self.expr.clone(), self.is_true, after_if_block);
        self.basic_block();
        f(&mut self);
        self.basic_block();
    }

    pub fn then_or_else(mut self, then_f: impl FnOnce(&mut Self), else_f: impl FnOnce(&mut Self)) {
        let else_block = self.block_label() + B::F::two();
        let main_flow_block = else_block + B::F::one();
        self.branch(self.expr.clone(), self.is_true, else_block);
        self.basic_block();
        then_f(&mut self);
        let instr = AsmInstruction::j(main_flow_block, &mut self);
        self.push(instr);
        self.basic_block();
        else_f(&mut self);
        self.basic_block();
    }

    fn branch(&mut self, expr: SymbolicLogic, is_true: bool, block: B::F) {
        match (expr, is_true) {
            (SymbolicLogic::Const(true), true) => {
                let instr = AsmInstruction::j(block, self);
                self.push(instr);
            }
            (SymbolicLogic::Const(true), false) => {}
            (SymbolicLogic::Const(false), true) => {}
            (SymbolicLogic::Const(false), false) => {
                let instr = AsmInstruction::j(block, self);
                self.push(instr);
            }
            (SymbolicLogic::Value(expr), true) => {
                let instr = AsmInstruction::BNEI(block, expr.0, B::F::one());
                self.push(instr);
            }
            (SymbolicLogic::Value(expr), false) => {
                let instr = AsmInstruction::BEQI(block, expr.0, B::F::one());
                self.push(instr);
            }
            (expr, true) => {
                let value = self.eval(expr);
                let instr = AsmInstruction::BNEI(block, value.0, B::F::one());
                self.push(instr);
            }
            (expr, false) => {
                let value = self.eval(expr);
                let instr = AsmInstruction::BEQI(block, value.0, B::F::one());
                self.push(instr);
            }
        }
    }
}

impl<'a, B: VmBuilder> BaseBuilder for IfFeltBuilder<'a, B> {}

impl<'a, B: VmBuilder> VmBuilder for IfFeltBuilder<'a, B> {
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

impl<'a, B: VmBuilder> IfFeltBuilder<'a, B> {
    pub fn then(mut self, f: impl FnOnce(&mut Self)) {
        // Get the label for the block after the if block, and generate the conditional branch
        // instruction to it, if the condition is not met.
        let after_if_block = self.block_label() + B::F::two();
        self.branch(
            self.lhs.clone(),
            self.rhs.clone(),
            self.is_eq,
            after_if_block,
        );
        // Generate the block for the then branch.
        self.basic_block();
        f(&mut self);
        // Generate the block for returning to the main flow.
        self.basic_block();
    }

    pub fn then_or_else(mut self, then_f: impl FnOnce(&mut Self), else_f: impl FnOnce(&mut Self)) {
        // Get the label for the else block, and the continued main flow block, and generate the
        // conditional branc instruction to it, if the condition is not met.
        let else_block = self.block_label() + B::F::two();
        let main_flow_block = else_block + B::F::one();
        self.branch(self.lhs.clone(), self.rhs.clone(), self.is_eq, else_block);
        // Generate the block for the then branch.
        self.basic_block();
        then_f(&mut self);
        // Generate the jump instruction to the main flow block.
        let instr = AsmInstruction::j(main_flow_block, &mut self);
        self.push(instr);
        // Generate the block for the else branch.
        self.basic_block();
        else_f(&mut self);
        // Generate the block for returning to the main flow.
        self.basic_block();
    }

    fn branch(&mut self, lhs: Symbolic<B::F>, rhs: Symbolic<B::F>, is_eq: bool, block: B::F) {
        match (lhs, rhs, is_eq) {
            (Symbolic::Const(lhs), Symbolic::Const(rhs), true) => {
                if lhs == rhs {
                    let instr = AsmInstruction::j(block, self);
                    self.push(instr);
                }
            }
            (Symbolic::Const(lhs), Symbolic::Const(rhs), false) => {
                if lhs != rhs {
                    let instr = AsmInstruction::j(block, self);
                    self.push(instr);
                }
            }
            (Symbolic::Const(lhs), Symbolic::Value(rhs), true) => {
                let instr = AsmInstruction::BNEI(block, rhs.0, lhs);
                self.push(instr);
            }
            (Symbolic::Const(lhs), Symbolic::Value(rhs), false) => {
                let instr = AsmInstruction::BEQI(block, rhs.0, lhs);
                self.push(instr);
            }
            (Symbolic::Const(lhs), rhs, true) => {
                let rhs = self.eval(rhs);
                let instr = AsmInstruction::BNEI(block, rhs.0, lhs);
                self.push(instr);
            }
            (Symbolic::Const(lhs), rhs, false) => {
                let rhs = self.eval(rhs);
                let instr = AsmInstruction::BEQI(block, rhs.0, lhs);
                self.push(instr);
            }
            (Symbolic::Value(lhs), Symbolic::Const(rhs), true) => {
                let instr = AsmInstruction::BNEI(block, lhs.0, rhs);
                self.push(instr);
            }
            (Symbolic::Value(lhs), Symbolic::Const(rhs), false) => {
                let instr = AsmInstruction::BEQI(block, lhs.0, rhs);
                self.push(instr);
            }
            (lhs, Symbolic::Const(rhs), true) => {
                let lhs = self.eval(lhs);
                let instr = AsmInstruction::BNEI(block, lhs.0, rhs);
                self.push(instr);
            }
            (lhs, Symbolic::Const(rhs), false) => {
                let lhs = self.eval(lhs);
                let instr = AsmInstruction::BEQI(block, lhs.0, rhs);
                self.push(instr);
            }
            (Symbolic::Value(lhs), Symbolic::Value(rhs), true) => {
                let instr = AsmInstruction::BNE(block, lhs.0, rhs.0);
                self.push(instr);
            }
            (Symbolic::Value(lhs), Symbolic::Value(rhs), false) => {
                let instr = AsmInstruction::BEQ(block, lhs.0, rhs.0);
                self.push(instr);
            }
            (Symbolic::Value(lhs), rhs, true) => {
                let rhs = self.eval(rhs);
                let instr = AsmInstruction::BNE(block, lhs.0, rhs.0);
                self.push(instr);
            }
            (Symbolic::Value(lhs), rhs, false) => {
                let rhs = self.eval(rhs);
                let instr = AsmInstruction::BEQ(block, lhs.0, rhs.0);
                self.push(instr);
            }
            (lhs, Symbolic::Value(rhs), true) => {
                let lhs = self.eval(lhs);
                let instr = AsmInstruction::BNE(block, lhs.0, rhs.0);
                self.push(instr);
            }
            (lhs, Symbolic::Value(rhs), false) => {
                let lhs = self.eval(lhs);
                let instr = AsmInstruction::BEQ(block, lhs.0, rhs.0);
                self.push(instr);
            }
            (lhs, rhs, true) => {
                let lhs = self.eval(lhs);
                let rhs = self.eval(rhs);
                let instr = AsmInstruction::BNE(block, lhs.0, rhs.0);
                self.push(instr);
            }
            (lhs, rhs, false) => {
                let lhs = self.eval(lhs);
                let rhs = self.eval(rhs);
                let instr = AsmInstruction::BEQ(block, lhs.0, rhs.0);
                self.push(instr);
            }
        }
    }
}

impl<'a, B: VmBuilder> VmBuilder for ConstantConditionBuilder<'a, B> {
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
