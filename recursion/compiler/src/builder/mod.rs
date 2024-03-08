use crate::asm::Instruction;
use crate::ir::Constant;
use crate::ir::Variable;

use crate::ir::Expression;
use crate::ir::Felt;

mod asm;

pub use asm::*;
use p3_field::PrimeField32;

pub trait Builder: Sized {
    type F: PrimeField32;
    /// Get stack memory.
    fn get_mem(&mut self, size: usize) -> i32;
    //  Allocate heap memory.
    // fn alloc(&mut self, size: Int) -> Int;

    fn push(&mut self, instruction: Instruction<Self::F>);

    fn basic_block(&mut self);

    fn uninit<T: Variable<Self>>(&mut self) -> T {
        T::uninit(self)
    }

    fn constant<T: Constant<Self>>(&mut self, value: T) -> T::Value {
        let var = T::Value::uninit(self);
        value.imm(var, self);
        var
    }

    fn assign<E: Expression<Self>>(&mut self, value: E::Value, expr: E) {
        expr.assign(value, self);
    }

    fn for_range(&mut self, start: Felt<Self::F>, end: Felt<Self::F>) -> ForBuilder<Self> {
        let loop_var = Felt::uninit(self);
        ForBuilder {
            builder: self,
            start,
            end,
            loop_var,
        }
    }
}

/// A builder for a for loop.
///
/// Starting with end < start will lead to undefined behavior!
pub struct ForBuilder<'a, B: Builder> {
    builder: &'a mut B,
    start: Felt<B::F>,
    end: Felt<B::F>,
    loop_var: Felt<B::F>,
}

impl<'a, B: Builder> Builder for ForBuilder<'a, B> {
    type F = B::F;
    fn get_mem(&mut self, size: usize) -> i32 {
        self.builder.get_mem(size)
    }

    fn push(&mut self, instruction: Instruction<B::F>) {
        self.builder.push(instruction);
    }

    fn basic_block(&mut self) {
        self.builder.basic_block();
    }
}

impl<'a, B: Builder> ForBuilder<'a, B> {
    pub fn for_each<Func>(&mut self, f: Func)
    where
        Func: FnOnce(&mut Self, Felt<B::F>),
    {
        let loop_var = self.loop_var;
        // A basic block for the loop body and loop step.
        self.basic_block();
        // The loop body.
        f(self, loop_var);
        // The loop step.
    }
}
