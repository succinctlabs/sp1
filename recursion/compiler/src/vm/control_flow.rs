use super::BasicBlock;
use super::VmBuilder;
use crate::syn::BaseBuilder;
use crate::vm::Int;

use crate::vm::AsmInstruction;

use crate::prelude::Symbolic;
use crate::prelude::SymbolicLogic;

use p3_field::AbstractField;

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

impl<'a, B: VmBuilder> IfBoolBuilder<'a, B> {
    pub fn then<Func>(self, f: Func)
    where
        Func: FnOnce(&mut B),
    {
        let Self {
            builder,
            expr,
            is_true,
        } = self;
        let after_if_block = builder.block_label() + B::F::two();
        Self::branch(expr, is_true, after_if_block, builder);
        builder.basic_block();
        f(builder);
        builder.basic_block();
    }

    pub fn then_or_else<ThenFunc, ElseFunc>(self, then_f: ThenFunc, else_f: ElseFunc)
    where
        ThenFunc: FnOnce(&mut B),
        ElseFunc: FnOnce(&mut B),
    {
        let Self {
            builder,
            expr,
            is_true,
        } = self;
        let else_block = builder.block_label() + B::F::two();
        let main_flow_block = else_block + B::F::one();
        Self::branch(expr, is_true, else_block, builder);
        builder.basic_block();
        then_f(builder);
        let instr = AsmInstruction::j(main_flow_block, builder);
        builder.push(instr);
        builder.basic_block();
        else_f(builder);
        builder.basic_block();
    }

    fn branch(expr: SymbolicLogic, is_true: bool, block: B::F, builder: &mut B) {
        match (expr, is_true) {
            (SymbolicLogic::Const(true), true) => {
                let instr = AsmInstruction::j(block, builder);
                builder.push(instr);
            }
            (SymbolicLogic::Const(true), false) => {}
            (SymbolicLogic::Const(false), true) => {}
            (SymbolicLogic::Const(false), false) => {
                let instr = AsmInstruction::j(block, builder);
                builder.push(instr);
            }
            (SymbolicLogic::Value(expr), true) => {
                let instr = AsmInstruction::BNEI(block, expr.0, B::F::one());
                builder.push(instr);
            }
            (SymbolicLogic::Value(expr), false) => {
                let instr = AsmInstruction::BEQI(block, expr.0, B::F::one());
                builder.push(instr);
            }
            (expr, true) => {
                let value = builder.eval(expr);
                let instr = AsmInstruction::BNEI(block, value.0, B::F::one());
                builder.push(instr);
            }
            (expr, false) => {
                let value = builder.eval(expr);
                let instr = AsmInstruction::BEQI(block, value.0, B::F::one());
                builder.push(instr);
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
    pub fn then<Func>(self, f: Func)
    where
        Func: FnOnce(&mut B),
    {
        let Self {
            builder,
            lhs,
            rhs,
            is_eq,
        } = self;
        // Get the label for the block after the if block, and generate the conditional branch
        // instruction to it, if the condition is not met.
        let after_if_block = builder.block_label() + B::F::two();
        Self::branch(lhs, rhs, is_eq, after_if_block, builder);
        // Generate the block for the then branch.
        builder.basic_block();
        f(builder);
        // Generate the block for returning to the main flow.
        builder.basic_block();
    }

    pub fn then_or_else<ThenFunc, ElseFunc>(self, then_f: ThenFunc, else_f: ElseFunc)
    where
        ThenFunc: FnOnce(&mut B),
        ElseFunc: FnOnce(&mut B),
    {
        let Self {
            builder,
            lhs,
            rhs,
            is_eq,
        } = self;
        // Get the label for the else block, and the continued main flow block, and generate the
        // conditional branc instruction to it, if the condition is not met.
        let else_block = builder.block_label() + B::F::two();
        let main_flow_block = else_block + B::F::one();
        Self::branch(lhs, rhs, is_eq, else_block, builder);
        // Generate the block for the then branch.
        builder.basic_block();
        then_f(builder);
        // Generate the jump instruction to the main flow block.
        let instr = AsmInstruction::j(main_flow_block, builder);
        builder.push(instr);
        // Generate the block for the else branch.
        builder.basic_block();
        else_f(builder);
        // Generate the block for returning to the main flow.
        builder.basic_block();
    }

    fn branch(lhs: Symbolic<B::F>, rhs: Symbolic<B::F>, is_eq: bool, block: B::F, builder: &mut B) {
        match (lhs, rhs, is_eq) {
            (Symbolic::Const(lhs), Symbolic::Const(rhs), true) => {
                if lhs == rhs {
                    let instr = AsmInstruction::j(block, builder);
                    builder.push(instr);
                }
            }
            (Symbolic::Const(lhs), Symbolic::Const(rhs), false) => {
                if lhs != rhs {
                    let instr = AsmInstruction::j(block, builder);
                    builder.push(instr);
                }
            }
            (Symbolic::Const(lhs), Symbolic::Value(rhs), true) => {
                let instr = AsmInstruction::BNEI(block, rhs.0, lhs);
                builder.push(instr);
            }
            (Symbolic::Const(lhs), Symbolic::Value(rhs), false) => {
                let instr = AsmInstruction::BEQI(block, rhs.0, lhs);
                builder.push(instr);
            }
            (Symbolic::Const(lhs), rhs, true) => {
                let rhs = builder.eval(rhs);
                let instr = AsmInstruction::BNEI(block, rhs.0, lhs);
                builder.push(instr);
            }
            (Symbolic::Const(lhs), rhs, false) => {
                let rhs = builder.eval(rhs);
                let instr = AsmInstruction::BEQI(block, rhs.0, lhs);
                builder.push(instr);
            }
            (Symbolic::Value(lhs), Symbolic::Const(rhs), true) => {
                let instr = AsmInstruction::BNEI(block, lhs.0, rhs);
                builder.push(instr);
            }
            (Symbolic::Value(lhs), Symbolic::Const(rhs), false) => {
                let instr = AsmInstruction::BEQI(block, lhs.0, rhs);
                builder.push(instr);
            }
            (lhs, Symbolic::Const(rhs), true) => {
                let lhs = builder.eval(lhs);
                let instr = AsmInstruction::BNEI(block, lhs.0, rhs);
                builder.push(instr);
            }
            (lhs, Symbolic::Const(rhs), false) => {
                let lhs = builder.eval(lhs);
                let instr = AsmInstruction::BEQI(block, lhs.0, rhs);
                builder.push(instr);
            }
            (Symbolic::Value(lhs), Symbolic::Value(rhs), true) => {
                let instr = AsmInstruction::BNE(block, lhs.0, rhs.0);
                builder.push(instr);
            }
            (Symbolic::Value(lhs), Symbolic::Value(rhs), false) => {
                let instr = AsmInstruction::BEQ(block, lhs.0, rhs.0);
                builder.push(instr);
            }
            (Symbolic::Value(lhs), rhs, true) => {
                let rhs = builder.eval(rhs);
                let instr = AsmInstruction::BNE(block, lhs.0, rhs.0);
                builder.push(instr);
            }
            (Symbolic::Value(lhs), rhs, false) => {
                let rhs = builder.eval(rhs);
                let instr = AsmInstruction::BEQ(block, lhs.0, rhs.0);
                builder.push(instr);
            }
            (lhs, Symbolic::Value(rhs), true) => {
                let lhs = builder.eval(lhs);
                let instr = AsmInstruction::BNE(block, lhs.0, rhs.0);
                builder.push(instr);
            }
            (lhs, Symbolic::Value(rhs), false) => {
                let lhs = builder.eval(lhs);
                let instr = AsmInstruction::BEQ(block, lhs.0, rhs.0);
                builder.push(instr);
            }
            (lhs, rhs, true) => {
                let lhs = builder.eval(lhs);
                let rhs = builder.eval(rhs);
                let instr = AsmInstruction::BNE(block, lhs.0, rhs.0);
                builder.push(instr);
            }
            (lhs, rhs, false) => {
                let lhs = builder.eval(lhs);
                let rhs = builder.eval(rhs);
                let instr = AsmInstruction::BEQ(block, lhs.0, rhs.0);
                builder.push(instr);
            }
        }
    }
}
