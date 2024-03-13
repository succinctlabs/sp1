use core::marker::PhantomData;

use super::{AssemblyCode, BasicBlock};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use p3_field::PrimeField32;
use sp1_recursion_core::runtime::Program;

use crate::asm::AsmInstruction;
use crate::ir::Builder;
use crate::ir::Usize;
use crate::ir::{Config, DslIR, Ext, Felt, Var};
use p3_field::Field;

pub(crate) const ZERO: i32 = 0;
pub(crate) const HEAP_PTR: i32 = -4;

pub type VmBuilder<F> = Builder<AsmConfig<F>>;

#[derive(Debug, Clone)]
pub struct AsmCompiler<F> {
    pub basic_blocks: Vec<BasicBlock<F>>,

    function_labels: BTreeMap<String, F>,
}

pub struct AsmConfig<F>(PhantomData<F>);

impl<F: Field> Config for AsmConfig<F> {
    type N = F;
    type F = F;
    type EF = F;
}

impl<F: PrimeField32> VmBuilder<F> {
    pub fn compile_to_asm(self) -> AssemblyCode<F> {
        let mut compiler = AsmCompiler::new();
        compiler.build(self.operations);
        compiler.code()
    }

    pub fn compile(self) -> Program<F> {
        let mut compiler = AsmCompiler::new();
        compiler.build(self.operations);
        compiler.compile()
    }
}

impl<F> Var<F> {
    pub fn fp(&self) -> i32 {
        -(self.0 as i32 + 4)
    }
}

impl<F> Felt<F> {
    pub fn fp(&self) -> i32 {
        -(self.0 as i32 + 4)
    }
}

impl<F, EF> Ext<F, EF> {
    pub fn fp(&self) -> i32 {
        -(self.0 as i32 + 4)
    }
}

impl<F: PrimeField32> AsmCompiler<F> {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            basic_blocks: vec![BasicBlock::new()],
            function_labels: BTreeMap::new(),
        }
    }

    pub fn build(&mut self, operations: Vec<DslIR<AsmConfig<F>>>) {
        for op in operations {
            match op {
                DslIR::Imm(dst, src) => {
                    self.push(AsmInstruction::IMM(dst.fp(), src));
                }
                DslIR::ImmFelt(dst, src) => {
                    self.push(AsmInstruction::IMM(dst.fp(), src));
                }
                DslIR::ImmExt(dst, src) => todo!(),
                DslIR::AddV(dst, lhs, rhs) => {
                    self.push(AsmInstruction::ADD(dst.fp(), lhs.fp(), rhs.fp()));
                }
                DslIR::AddVI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::ADDI(dst.fp(), lhs.fp(), rhs));
                }
                DslIR::AddF(dst, lhs, rhs) => {
                    self.push(AsmInstruction::ADD(dst.fp(), lhs.fp(), rhs.fp()));
                }
                DslIR::AddFI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::ADDI(dst.fp(), lhs.fp(), rhs));
                }
                DslIR::AddE(dst, lhs, rhs) => todo!(),
                DslIR::AddEI(dst, lhs, rhs) => todo!(),
                DslIR::SubV(dst, lhs, rhs) => {
                    self.push(AsmInstruction::SUB(dst.fp(), lhs.fp(), rhs.fp()));
                }
                DslIR::SubVI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::SUBI(dst.fp(), lhs.fp(), rhs));
                }
                DslIR::SubVIN(dst, lhs, rhs) => {
                    self.push(AsmInstruction::SUBIN(dst.fp(), lhs, rhs.fp()));
                }
                DslIR::SubF(dst, lhs, rhs) => {
                    self.push(AsmInstruction::SUB(dst.fp(), lhs.fp(), rhs.fp()));
                }
                DslIR::SubFI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::SUBI(dst.fp(), lhs.fp(), rhs));
                }
                DslIR::SubFIN(dst, lhs, rhs) => {
                    self.push(AsmInstruction::SUBIN(dst.fp(), lhs, rhs.fp()));
                }
                DslIR::SubE(dst, lhs, rhs) => todo!(),
                DslIR::SubEI(dst, lhs, rhs) => todo!(),
                DslIR::MulV(dst, lhs, rhs) => {
                    self.push(AsmInstruction::MUL(dst.fp(), lhs.fp(), rhs.fp()));
                }
                DslIR::MulVI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::MULI(dst.fp(), lhs.fp(), rhs));
                }
                DslIR::MulF(dst, lhs, rhs) => {
                    self.push(AsmInstruction::MUL(dst.fp(), lhs.fp(), rhs.fp()));
                }
                DslIR::MulFI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::MULI(dst.fp(), lhs.fp(), rhs));
                }
                DslIR::MulE(dst, lhs, rhs) => todo!(),
                DslIR::MulEI(dst, lhs, rhs) => todo!(),
                DslIR::MulEF(dst, lhs, rhs) => todo!(),
                DslIR::MulEFI(dst, lhs, rhs) => todo!(),
                DslIR::DivF(dst, lhs, rhs) => {
                    self.push(AsmInstruction::DIV(dst.fp(), lhs.fp(), rhs.fp()));
                }
                DslIR::DivFI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::DIVI(dst.fp(), lhs.fp(), rhs));
                }
                DslIR::DivFIN(dst, lhs, rhs) => {
                    self.push(AsmInstruction::DIVIN(dst.fp(), lhs, rhs.fp()));
                }
                DslIR::DivE(dst, lhs, rhs) => todo!(),
                DslIR::DivEI(dst, lhs, rhs) => todo!(),
                DslIR::AssertEqV(lhs, rhs) => todo!(),
                DslIR::IfEq(lhs, rhs, then_block, else_block) => {
                    let if_compiler = IfCompiler {
                        builder: self,
                        lhs,
                        rhs: VarOrConst::Var(rhs),
                        is_eq: true,
                    };
                    if else_block.is_empty() {
                        if_compiler.then(|builder| builder.build(then_block));
                    } else {
                        if_compiler.then_or_else(
                            |builder| builder.build(then_block),
                            |builder| builder.build(else_block),
                        );
                    }
                }
                DslIR::IfNe(lhs, rhs, then_block, else_block) => {
                    let if_compiler = IfCompiler {
                        builder: self,
                        lhs,
                        rhs: VarOrConst::Var(rhs),
                        is_eq: false,
                    };
                    if else_block.is_empty() {
                        if_compiler.then(|builder| builder.build(then_block));
                    } else {
                        if_compiler.then_or_else(
                            |builder| builder.build(then_block),
                            |builder| builder.build(else_block),
                        );
                    }
                }
                DslIR::IfEqI(lhs, rhs, then_block, else_block) => {
                    let if_compiler = IfCompiler {
                        builder: self,
                        lhs,
                        rhs: VarOrConst::Const(rhs),
                        is_eq: true,
                    };
                    if else_block.is_empty() {
                        if_compiler.then(|builder| builder.build(then_block));
                    } else {
                        if_compiler.then_or_else(
                            |builder| builder.build(then_block),
                            |builder| builder.build(else_block),
                        );
                    }
                }
                DslIR::IfNeI(lhs, rhs, then_block, else_block) => {
                    let if_compiler = IfCompiler {
                        builder: self,
                        lhs,
                        rhs: VarOrConst::Const(rhs),
                        is_eq: false,
                    };
                    if else_block.is_empty() {
                        if_compiler.then(|builder| builder.build(then_block));
                    } else {
                        if_compiler.then_or_else(
                            |builder| builder.build(then_block),
                            |builder| builder.build(else_block),
                        );
                    }
                }
                _ => todo!(),
            }
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

    fn basic_block(&mut self) {
        self.basic_blocks.push(BasicBlock::new());
    }

    fn block_label(&mut self) -> F {
        F::from_canonical_usize(self.basic_blocks.len() - 1)
    }

    fn get_block_mut(&mut self, label: F) -> &mut BasicBlock<F> {
        &mut self.basic_blocks[label.as_canonical_u32() as usize]
    }

    fn push_to_block(&mut self, block_label: F, instruction: AsmInstruction<F>) {
        self.basic_blocks
            .get_mut(block_label.as_canonical_u32() as usize)
            .unwrap_or_else(|| panic!("Missing block at label: {:?}", block_label))
            .push(instruction);
    }

    fn push(&mut self, instruction: AsmInstruction<F>) {
        self.basic_blocks.last_mut().unwrap().push(instruction);
    }
}

pub enum VarOrConst<F> {
    Var(Var<F>),
    Const(F),
}

pub struct IfCompiler<'a, F> {
    builder: &'a mut AsmCompiler<F>,
    lhs: Var<F>,
    rhs: VarOrConst<F>,
    is_eq: bool,
}

impl<'a, F: PrimeField32> IfCompiler<'a, F> {
    pub fn then<Func>(self, f: Func)
    where
        Func: FnOnce(&mut AsmCompiler<F>),
    {
        let Self {
            builder,
            lhs,
            rhs,
            is_eq,
        } = self;
        // Get the label for the block after the if block, and generate the conditional branch
        // instruction to it, if the condition is not met.
        let after_if_block = builder.block_label() + F::two();
        Self::branch(lhs, rhs, is_eq, after_if_block, builder);
        // Generate the block for the then branch.
        builder.basic_block();
        f(builder);
        // Generate the block for returning to the main flow.
        builder.basic_block();
    }

    pub fn then_or_else<ThenFunc, ElseFunc>(self, then_f: ThenFunc, else_f: ElseFunc)
    where
        ThenFunc: FnOnce(&mut AsmCompiler<F>),
        ElseFunc: FnOnce(&mut AsmCompiler<F>),
    {
        let Self {
            builder,
            lhs,
            rhs,
            is_eq,
        } = self;
        // Get the label for the else block, and the continued main flow block, and generate the
        // conditional branc instruction to it, if the condition is not met.
        let else_block = builder.block_label() + F::two();
        let main_flow_block = else_block + F::one();
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

    fn branch(
        lhs: Var<F>,
        rhs: VarOrConst<F>,
        is_eq: bool,
        block: F,
        builder: &mut AsmCompiler<F>,
    ) {
        match (rhs, is_eq) {
            (VarOrConst::Const(rhs), true) => {
                let instr = AsmInstruction::BNEI(block, lhs.fp(), rhs);
                builder.push(instr);
            }
            (VarOrConst::Const(rhs), false) => {
                let instr = AsmInstruction::BEQI(block, lhs.fp(), rhs);
                builder.push(instr);
            }
            (VarOrConst::Var(rhs), true) => {
                let instr = AsmInstruction::BNE(block, lhs.fp(), rhs.fp());
                builder.push(instr);
            }
            (VarOrConst::Var(rhs), false) => {
                let instr = AsmInstruction::BEQ(block, lhs.fp(), rhs.fp());
                builder.push(instr);
            }
        }
    }
}

/// A builder for a for loop.
///
/// Starting with end < start will lead to undefined behavior!
pub struct ForCompiler<'a, F> {
    builder: &'a mut AsmCompiler<F>,
    start: Usize<F>,
    end: Usize<F>,
    loop_var: Var<F>,
}
