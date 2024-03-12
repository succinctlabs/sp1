use super::IfBoolBuilder;
use super::{AssemblyCode, BasicBlock, IfFeltBuilder};
use crate::syn::{BaseBuilder, Condition, FieldBuilder};
use crate::vm::Felt;
use crate::vm::Int;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use p3_field::PrimeField32;
use sp1_recursion_core::runtime::Program;

use crate::syn::Variable;
use crate::vm::AsmInstruction;

use crate::prelude::Symbolic;
use crate::prelude::SymbolicLogic;

pub trait VmBuilder: BaseBuilder {
    type F: PrimeField32;
    /// Get stack memory.
    fn get_mem(&mut self, size: usize) -> i32;
    //  Allocate heap memory.
    fn alloc(&mut self, size: Int) -> Int;

    fn push(&mut self, instruction: AsmInstruction<Self::F>);

    fn get_block_mut(&mut self, label: Self::F) -> &mut BasicBlock<Self::F>;

    fn basic_block(&mut self);

    fn block_label(&mut self) -> Self::F;

    fn push_to_block(&mut self, block_label: Self::F, instruction: AsmInstruction<Self::F>) {
        self.get_block_mut(block_label).push(instruction);
    }

    fn uninit<T: Variable<Self>>(&mut self) -> T {
        T::uninit(self)
    }

    fn if_eq<E1, E2>(&mut self, lhs: E1, rhs: E2) -> IfFeltBuilder<Self>
    where
        E1: Into<Symbolic<Self::F>>,
        E2: Into<Symbolic<Self::F>>,
    {
        IfFeltBuilder {
            builder: self,
            lhs: lhs.into(),
            rhs: rhs.into(),
            is_eq: true,
        }
    }

    fn if_neq<E1, E2>(&mut self, lhs: E1, rhs: E2) -> IfFeltBuilder<Self>
    where
        E1: Into<Symbolic<Self::F>>,
        E2: Into<Symbolic<Self::F>>,
    {
        IfFeltBuilder {
            builder: self,
            lhs: lhs.into(),
            rhs: rhs.into(),
            is_eq: false,
        }
    }

    fn assert_eq<E1, E2>(&mut self, lhs: E1, rhs: E2)
    where
        E1: Into<Symbolic<Self::F>>,
        E2: Into<Symbolic<Self::F>>,
    {
        self.if_neq(lhs, rhs)
            .then(|builder| builder.push(AsmInstruction::TRAP));
    }

    fn assert_ne<E1, E2>(&mut self, lhs: E1, rhs: E2)
    where
        E1: Into<Symbolic<Self::F>>,
        E2: Into<Symbolic<Self::F>>,
    {
        self.if_eq(lhs, rhs)
            .then(|builder| builder.push(AsmInstruction::TRAP));
    }

    fn if_false<E>(&mut self, expr: E) -> IfBoolBuilder<Self>
    where
        E: Into<SymbolicLogic>,
    {
        IfBoolBuilder {
            builder: self,
            expr: expr.into(),
            is_true: false,
        }
    }

    fn assert<E>(&mut self, expr: E)
    where
        E: Into<SymbolicLogic>,
    {
        self.if_false(expr)
            .then(|builder| builder.push(AsmInstruction::TRAP));
    }

    fn assert_not<E>(&mut self, expr: E)
    where
        E: Into<SymbolicLogic>,
    {
        let expr: SymbolicLogic = expr.into();
        expr.if_condition(self)
            .then(|builder| builder.push(AsmInstruction::TRAP));
    }
}

#[derive(Debug, Clone)]
pub struct AsmBuilder<F> {
    fp_offset: i32,

    pub basic_blocks: Vec<BasicBlock<F>>,

    function_labels: BTreeMap<String, F>,
}

impl<F: PrimeField32> BaseBuilder for AsmBuilder<F> {}

impl<VB: VmBuilder> FieldBuilder<VB::F> for VB {
    type Felt = Felt<VB::F>;
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

impl<F: PrimeField32> VmBuilder for AsmBuilder<F> {
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
