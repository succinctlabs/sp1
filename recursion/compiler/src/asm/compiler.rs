use core::marker::PhantomData;

use super::{AssemblyCode, BasicBlock};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use p3_field::ExtensionField;
use p3_field::PrimeField;
use p3_field::PrimeField32;
use p3_field::TwoAdicField;
use sp1_recursion_core::runtime::Program;
use sp1_recursion_core::runtime::STACK_SIZE;

use crate::asm::AsmInstruction;
use crate::ir::Builder;
use crate::ir::Usize;
use crate::ir::{Config, DslIR, Ext, Felt, Ptr, Var};
use crate::prelude::Array;

pub(crate) const STACK_START_OFFSET: i32 = 16;

pub(crate) const ZERO: i32 = 0;
pub(crate) const HEAP_PTR: i32 = -4;

#[allow(dead_code)]
pub(crate) const A0: i32 = -8;
#[allow(dead_code)]
pub(crate) const A1: i32 = -12;

pub type VmBuilder<F, EF> = Builder<AsmConfig<F, EF>>;

#[derive(Debug, Clone)]
pub struct AsmCompiler<F, EF> {
    pub basic_blocks: Vec<BasicBlock<F, EF>>,

    function_labels: BTreeMap<String, F>,
}

#[derive(Debug, Clone)]
pub struct AsmConfig<F, EF>(PhantomData<(F, EF)>);

impl<F: PrimeField + TwoAdicField, EF: ExtensionField<F>> Config for AsmConfig<F, EF> {
    type N = F;
    type F = F;
    type EF = EF;
}

impl<F: PrimeField32 + TwoAdicField, EF: ExtensionField<F>> VmBuilder<F, EF> {
    pub fn compile_to_asm(self) -> AssemblyCode<F, EF> {
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
    fn fp(&self) -> i32 {
        -((self.0 as i32) * 3 + 1 + STACK_START_OFFSET)
    }
}

impl<F> Felt<F> {
    fn fp(&self) -> i32 {
        -((self.0 as i32) * 3 + 2 + STACK_START_OFFSET)
    }
}

impl<F> Ptr<F> {
    fn fp(&self) -> i32 {
        self.address.fp()
    }
}

impl<F, EF> Ext<F, EF> {
    pub fn fp(&self) -> i32 {
        -((self.0 as i32) * 3 + STACK_START_OFFSET)
    }
}

impl<F: PrimeField32 + TwoAdicField, EF: ExtensionField<F>> AsmCompiler<F, EF> {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            basic_blocks: vec![BasicBlock::new()],
            function_labels: BTreeMap::new(),
        }
    }

    pub fn build(&mut self, operations: Vec<DslIR<AsmConfig<F, EF>>>) {
        if self.block_label().is_zero() {
            // Set the heap pointer value according to stack size
            let stack_size = F::from_canonical_usize(STACK_SIZE + 4);
            self.push(AsmInstruction::IMM(HEAP_PTR, stack_size));
        }
        for op in operations.clone() {
            match op {
                DslIR::Imm(dst, src) => {
                    self.push(AsmInstruction::IMM(dst.fp(), src));
                }
                DslIR::ImmFelt(dst, src) => {
                    self.push(AsmInstruction::IMM(dst.fp(), src));
                }
                DslIR::ImmExt(dst, src) => {
                    self.push(AsmInstruction::EIMM(dst.fp(), src));
                }
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
                DslIR::AddE(dst, lhs, rhs) => {
                    self.push(AsmInstruction::EADD(dst.fp(), lhs.fp(), rhs.fp()));
                }
                DslIR::AddEI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::EADDI(dst.fp(), lhs.fp(), rhs));
                }
                DslIR::AddEF(dst, lhs, rhs) => {
                    self.push(AsmInstruction::EADDF(dst.fp(), lhs.fp(), rhs.fp()));
                }
                DslIR::AddEFFI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::FADDEI(dst.fp(), lhs.fp(), rhs));
                }
                DslIR::AddEFI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::EADDI(
                        dst.fp(),
                        lhs.fp(),
                        EF::from_base(rhs),
                    ));
                }
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
                DslIR::NegV(dst, src) => {
                    self.push(AsmInstruction::SUBIN(dst.fp(), F::one(), src.fp()));
                }
                DslIR::NegF(dst, src) => {
                    self.push(AsmInstruction::SUBIN(dst.fp(), F::one(), src.fp()));
                }
                DslIR::DivF(dst, lhs, rhs) => {
                    self.push(AsmInstruction::DIV(dst.fp(), lhs.fp(), rhs.fp()));
                }
                DslIR::DivFI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::DIVI(dst.fp(), lhs.fp(), rhs));
                }
                DslIR::DivFIN(dst, lhs, rhs) => {
                    self.push(AsmInstruction::DIVIN(dst.fp(), lhs, rhs.fp()));
                }
                DslIR::InvV(dst, src) => {
                    self.push(AsmInstruction::DIVIN(dst.fp(), F::one(), src.fp()));
                }
                DslIR::InvF(dst, src) => {
                    self.push(AsmInstruction::DIVIN(dst.fp(), F::one(), src.fp()));
                }
                DslIR::DivEF(dst, lhs, rhs) => {
                    self.push(AsmInstruction::EDIVF(dst.fp(), lhs.fp(), rhs.fp()));
                }
                DslIR::DivEFI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::EDIVI(
                        dst.fp(),
                        lhs.fp(),
                        EF::from_base(rhs),
                    ));
                }
                DslIR::DivEIN(dst, lhs, rhs) => {
                    self.push(AsmInstruction::EDIVIN(dst.fp(), lhs, rhs.fp()));
                }
                DslIR::DivEFIN(dst, lhs, rhs) => {
                    self.push(AsmInstruction::EDIVIN(
                        dst.fp(),
                        EF::from_base(lhs),
                        rhs.fp(),
                    ));
                }
                DslIR::DivE(dst, lhs, rhs) => {
                    self.push(AsmInstruction::EDIV(dst.fp(), lhs.fp(), rhs.fp()));
                }
                DslIR::DivEI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::EDIVI(dst.fp(), lhs.fp(), rhs));
                }
                DslIR::InvE(dst, src) => {
                    self.push(AsmInstruction::EDIVIN(dst.fp(), EF::one(), src.fp()));
                }
                DslIR::SubEFIN(dst, lhs, rhs) => {
                    self.push(AsmInstruction::ESUBIN(
                        dst.fp(),
                        EF::from_base(lhs),
                        rhs.fp(),
                    ));
                }
                DslIR::SubEF(dst, lhs, rhs) => {
                    self.push(AsmInstruction::ESUBF(dst.fp(), lhs.fp(), rhs.fp()));
                }
                DslIR::SubEFI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::ESUBI(
                        dst.fp(),
                        lhs.fp(),
                        EF::from_base(rhs),
                    ));
                }
                DslIR::SubEIN(dst, lhs, rhs) => {
                    self.push(AsmInstruction::ESUBIN(dst.fp(), lhs, rhs.fp()));
                }
                DslIR::SubE(dst, lhs, rhs) => {
                    self.push(AsmInstruction::ESUB(dst.fp(), lhs.fp(), rhs.fp()));
                }
                DslIR::SubEI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::ESUBI(dst.fp(), lhs.fp(), rhs));
                }
                DslIR::NegE(dst, src) => {
                    self.push(AsmInstruction::ESUBIN(dst.fp(), EF::one(), src.fp()));
                }
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
                DslIR::MulE(dst, lhs, rhs) => {
                    self.push(AsmInstruction::EMUL(dst.fp(), lhs.fp(), rhs.fp()));
                }
                DslIR::MulEI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::EMULI(dst.fp(), lhs.fp(), rhs));
                }
                DslIR::MulEF(dst, lhs, rhs) => {
                    self.push(AsmInstruction::EMULF(dst.fp(), lhs.fp(), rhs.fp()));
                }
                DslIR::MulEFI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::EMULI(
                        dst.fp(),
                        lhs.fp(),
                        EF::from_base(rhs),
                    ));
                }
                DslIR::IfEq(lhs, rhs, then_block, else_block) => {
                    let if_compiler = IfCompiler {
                        compiler: self,
                        lhs: lhs.fp(),
                        rhs: ValueOrConst::Val(rhs.fp()),
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
                        compiler: self,
                        lhs: lhs.fp(),
                        rhs: ValueOrConst::Val(rhs.fp()),
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
                        compiler: self,
                        lhs: lhs.fp(),
                        rhs: ValueOrConst::Const(rhs),
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
                        compiler: self,
                        lhs: lhs.fp(),
                        rhs: ValueOrConst::Const(rhs),
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
                DslIR::For(start, end, loop_var, block) => {
                    let for_compiler = ForCompiler {
                        compiler: self,
                        start,
                        end,
                        loop_var,
                    };
                    for_compiler.for_each(move |_, builder| builder.build(block));
                }
                DslIR::AssertEqV(lhs, rhs) => {
                    // If lhs != rhs, execute TRAP
                    self.assert(lhs.fp(), ValueOrConst::Val(rhs.fp()), false)
                }
                DslIR::AssertEqVI(lhs, rhs) => {
                    // If lhs != rhs, execute TRAP
                    self.assert(lhs.fp(), ValueOrConst::Const(rhs), false)
                }
                DslIR::AssertNeV(lhs, rhs) => {
                    // If lhs == rhs, execute TRAP
                    self.assert(lhs.fp(), ValueOrConst::Val(rhs.fp()), true)
                }
                DslIR::AssertNeVI(lhs, rhs) => {
                    // If lhs == rhs, execute TRAP
                    self.assert(lhs.fp(), ValueOrConst::Const(rhs), true)
                }
                DslIR::AssertEqF(lhs, rhs) => {
                    // If lhs != rhs, execute TRAP
                    self.assert(lhs.fp(), ValueOrConst::Val(rhs.fp()), false)
                }
                DslIR::AssertEqFI(lhs, rhs) => {
                    // If lhs != rhs, execute TRAP
                    self.assert(lhs.fp(), ValueOrConst::Const(rhs), false)
                }
                DslIR::AssertNeF(lhs, rhs) => {
                    // If lhs == rhs, execute TRAP
                    self.assert(lhs.fp(), ValueOrConst::Val(rhs.fp()), true)
                }
                DslIR::AssertNeFI(lhs, rhs) => {
                    // If lhs == rhs, execute TRAP
                    self.assert(lhs.fp(), ValueOrConst::Const(rhs), true)
                }
                DslIR::AssertEqE(lhs, rhs) => {
                    // If lhs != rhs, execute TRAP
                    self.assert(lhs.fp(), ValueOrConst::ExtVal(rhs.fp()), false)
                }
                DslIR::AssertEqEI(lhs, rhs) => {
                    // If lhs != rhs, execute TRAP
                    self.assert(lhs.fp(), ValueOrConst::ExtConst(rhs), false)
                }
                DslIR::AssertNeE(lhs, rhs) => {
                    // If lhs == rhs, execute TRAP
                    self.assert(lhs.fp(), ValueOrConst::ExtVal(rhs.fp()), true)
                }
                DslIR::AssertNeEI(lhs, rhs) => {
                    // If lhs == rhs, execute TRAP
                    self.assert(lhs.fp(), ValueOrConst::ExtConst(rhs), true)
                }
                DslIR::Alloc(ptr, len) => {
                    self.alloc(ptr, len);
                }
                DslIR::LoadV(var, ptr) => self.push(AsmInstruction::LW(var.fp(), ptr.fp())),
                DslIR::LoadF(var, ptr) => self.push(AsmInstruction::LW(var.fp(), ptr.fp())),
                DslIR::LoadE(var, ptr) => self.push(AsmInstruction::LE(var.fp(), ptr.fp())),
                DslIR::StoreV(ptr, var) => self.push(AsmInstruction::SW(ptr.fp(), var.fp())),
                DslIR::StoreF(ptr, var) => self.push(AsmInstruction::SW(ptr.fp(), var.fp())),
                DslIR::StoreE(ptr, var) => self.push(AsmInstruction::SE(ptr.fp(), var.fp())),
                DslIR::HintBitsU(dst, src) => match (dst, src) {
                    (Array::Dyn(dst, _), Usize::Var(src)) => {
                        self.push(AsmInstruction::HintBits(dst.fp(), src.fp()));
                    }
                    _ => unimplemented!(),
                },
                DslIR::HintBitsF(dst, src) => match dst {
                    Array::Dyn(dst, _) => {
                        self.push(AsmInstruction::HintBits(dst.fp(), src.fp()));
                    }
                    _ => unimplemented!(),
                },
                DslIR::HintBitsV(dst, src) => match dst {
                    Array::Dyn(dst, _) => {
                        self.push(AsmInstruction::HintBits(dst.fp(), src.fp()));
                    }
                    _ => unimplemented!(),
                },
                DslIR::Num2BitsF(_, _) => unimplemented!(),
                DslIR::Num2BitsV(_, _) => unimplemented!(),
                DslIR::Poseidon2PermuteBabyBear(dst, src) => match (dst, src) {
                    (Array::Dyn(dst, _), Array::Dyn(src, _)) => {
                        self.push(AsmInstruction::Poseidon2Permute(dst.fp(), src.fp()))
                    }
                    _ => unimplemented!(),
                },
                DslIR::ReverseBitsLen(_, _, _) => unimplemented!(),
                DslIR::TwoAdicGenerator(_, _) => unimplemented!(),
                DslIR::ExpUsizeV(_, _, _) => unimplemented!(),
                DslIR::ExpUsizeF(_, _, _) => unimplemented!(),
                DslIR::Error() => self.push(AsmInstruction::TRAP),
                DslIR::PrintF(dst) => self.push(AsmInstruction::PrintF(dst.fp())),
                DslIR::PrintV(dst) => self.push(AsmInstruction::PrintV(dst.fp())),
                DslIR::PrintE(dst) => self.push(AsmInstruction::PrintE(dst.fp())),
                DslIR::Ext2Felt(dst, src) => match (dst, src) {
                    (Array::Dyn(dst, _), src) => {
                        self.push(AsmInstruction::Ext2Felt(dst.fp(), src.fp()))
                    }
                    _ => unimplemented!(),
                },
                _ => unimplemented!(),
            }
        }
    }

    pub fn alloc(&mut self, ptr: Ptr<F>, len: Usize<F>) {
        // Load the current heap ptr address to the stack value and advance the heap ptr.
        match len {
            Usize::Const(len) => {
                let len = F::from_canonical_usize(len);
                self.push(AsmInstruction::ADDI(ptr.fp(), HEAP_PTR, F::zero()));
                self.push(AsmInstruction::ADDI(HEAP_PTR, HEAP_PTR, len));
            }
            Usize::Var(len) => {
                self.push(AsmInstruction::ADDI(ptr.fp(), HEAP_PTR, F::zero()));
                self.push(AsmInstruction::ADD(HEAP_PTR, HEAP_PTR, len.fp()));
            }
        }
    }

    pub fn assert(&mut self, lhs: i32, rhs: ValueOrConst<F, EF>, is_eq: bool) {
        let if_compiler = IfCompiler {
            compiler: self,
            lhs,
            rhs,
            is_eq,
        };
        if_compiler.then(|builder| builder.push(AsmInstruction::TRAP));
    }

    pub fn code(self) -> AssemblyCode<F, EF> {
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

    fn push_to_block(&mut self, block_label: F, instruction: AsmInstruction<F, EF>) {
        self.basic_blocks
            .get_mut(block_label.as_canonical_u32() as usize)
            .unwrap_or_else(|| panic!("Missing block at label: {:?}", block_label))
            .push(instruction);
    }

    fn push(&mut self, instruction: AsmInstruction<F, EF>) {
        self.basic_blocks.last_mut().unwrap().push(instruction);
    }
}

pub enum ValueOrConst<F, EF> {
    Val(i32),
    ExtVal(i32),
    Const(F),
    ExtConst(EF),
}

pub struct IfCompiler<'a, F, EF> {
    compiler: &'a mut AsmCompiler<F, EF>,
    lhs: i32,
    rhs: ValueOrConst<F, EF>,
    is_eq: bool,
}

impl<'a, F: PrimeField32 + TwoAdicField, EF: ExtensionField<F>> IfCompiler<'a, F, EF> {
    pub fn then<Func>(self, f: Func)
    where
        Func: FnOnce(&mut AsmCompiler<F, EF>),
    {
        let Self {
            compiler,
            lhs,
            rhs,
            is_eq,
        } = self;
        // Get the label for the current block which will contain the branch.
        let if_branching_block = compiler.block_label();
        // Generate the blocks for the then branch.
        compiler.basic_block();
        f(compiler);
        // Generate the block for returning to the main flow.
        compiler.basic_block();
        // Get the block label for the after if block.
        let after_if_block = compiler.block_label();
        // Get the branch instruction to push to the `if_branching_block`.
        let instr = Self::branch(lhs, rhs, is_eq, after_if_block);
        compiler.push_to_block(if_branching_block, instr);
    }

    pub fn then_or_else<ThenFunc, ElseFunc>(self, then_f: ThenFunc, else_f: ElseFunc)
    where
        ThenFunc: FnOnce(&mut AsmCompiler<F, EF>),
        ElseFunc: FnOnce(&mut AsmCompiler<F, EF>),
    {
        let Self {
            compiler,
            lhs,
            rhs,
            is_eq,
        } = self;
        // Get the label for the current block, so we can generate the jump instruction into it.
        // conditional branc instruction to it, if the condition is not met.
        let if_branching_block = compiler.block_label();
        // Generate the block for the then branch.
        compiler.basic_block();
        then_f(compiler);
        let last_if_block = compiler.block_label();
        // Generate the block for the else branch.
        compiler.basic_block();
        let else_block = compiler.block_label();
        else_f(compiler);
        // Generate the jump instruction to the else block
        let instr = Self::branch(lhs, rhs, is_eq, else_block);
        compiler.push_to_block(if_branching_block, instr);
        // Generate the block for returning to the main flow.
        compiler.basic_block();

        // Get the label for the main flow block and generate the jump instruction to it.
        let main_flow_block = compiler.block_label();
        let instr = AsmInstruction::j(main_flow_block);
        compiler.push_to_block(last_if_block, instr);
    }

    fn branch(lhs: i32, rhs: ValueOrConst<F, EF>, is_eq: bool, block: F) -> AsmInstruction<F, EF> {
        match (rhs, is_eq) {
            (ValueOrConst::Const(rhs), true) => AsmInstruction::BNEI(block, lhs, rhs),
            (ValueOrConst::Const(rhs), false) => AsmInstruction::BEQI(block, lhs, rhs),
            (ValueOrConst::ExtConst(rhs), true) => AsmInstruction::EBNEI(block, lhs, rhs),
            (ValueOrConst::ExtConst(rhs), false) => AsmInstruction::EBEQI(block, lhs, rhs),
            (ValueOrConst::Val(rhs), true) => AsmInstruction::BNE(block, lhs, rhs),
            (ValueOrConst::Val(rhs), false) => AsmInstruction::BEQ(block, lhs, rhs),
            (ValueOrConst::ExtVal(rhs), true) => AsmInstruction::EBNE(block, lhs, rhs),
            (ValueOrConst::ExtVal(rhs), false) => AsmInstruction::EBEQ(block, lhs, rhs),
        }
    }
}

/// A builder for a for loop.
///
/// Starting with end < start will lead to undefined behavior!
pub struct ForCompiler<'a, F, EF> {
    compiler: &'a mut AsmCompiler<F, EF>,
    start: Usize<F>,
    end: Usize<F>,
    loop_var: Var<F>,
}

impl<'a, F: PrimeField32 + TwoAdicField, EF: ExtensionField<F>> ForCompiler<'a, F, EF> {
    pub(super) fn for_each(mut self, f: impl FnOnce(Var<F>, &mut AsmCompiler<F, EF>)) {
        // The function block structure:
        // - Setting the loop range
        // - Executing the loop body and incrementing the loop variable
        // - the loop condition
        // Set the loop variable to the start of the range.
        self.set_loop_var();
        // Save the label of the for loop call
        let loop_call_label = self.compiler.block_label();
        // A basic block for the loop body
        self.compiler.basic_block();
        // Save the loop body label for the loop condition.
        let loop_label = self.compiler.block_label();
        // The loop body.
        f(self.loop_var, self.compiler);
        self.compiler.push(AsmInstruction::ADDI(
            self.loop_var.fp(),
            self.loop_var.fp(),
            F::one(),
        ));

        // loop_var, loop_var + B::F::one());
        // Add a basic block for the loop condition.
        self.compiler.basic_block();
        // Jump to loop body if the loop condition still holds.
        self.jump_to_loop_body(loop_label);
        // Add a jump instruction to the loop condition in the following block
        let label = self.compiler.block_label();
        let instr = AsmInstruction::j(label);
        self.compiler.push_to_block(loop_call_label, instr);
    }

    fn set_loop_var(&mut self) {
        match self.start {
            Usize::Const(start) => {
                self.compiler.push(AsmInstruction::IMM(
                    self.loop_var.fp(),
                    F::from_canonical_usize(start),
                ));
            }
            Usize::Var(var) => {
                self.compiler.push(AsmInstruction::ADDI(
                    self.loop_var.fp(),
                    var.fp(),
                    F::zero(),
                ));
            }
        }
    }

    fn jump_to_loop_body(&mut self, loop_label: F) {
        match self.end {
            Usize::Const(end) => {
                let instr = AsmInstruction::BNEI(
                    loop_label,
                    self.loop_var.fp(),
                    F::from_canonical_usize(end),
                );
                self.compiler.push(instr);
            }
            Usize::Var(end) => {
                let instr = AsmInstruction::BNE(loop_label, self.loop_var.fp(), end.fp());
                self.compiler.push(instr);
            }
        }
    }
}
