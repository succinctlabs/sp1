use crate::asm::Instruction;
use crate::ir::Builder;
use crate::ir::Expression;
use crate::ir::SizedVariable;
use crate::ir::Symbolic;
use crate::ir::Variable;
use core::fmt;
use core::marker::PhantomData;
use p3_field::AbstractField;

use core::ops::{Add, Div, Mul, Neg, Sub};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Felt<F>(pub i32, PhantomData<F>);

impl<B: Builder> Variable<B> for Felt<B::F> {
    fn uninit(builder: &mut B) -> Self {
        Felt(builder.get_mem(4), PhantomData)
    }
}

impl<B: Builder> SizedVariable<B> for Felt<B::F> {
    fn size_of() -> usize {
        1
    }
}

impl<B: Builder> Expression<B> for Felt<B::F> {
    type Value = Felt<B::F>;

    fn assign(&self, value: Felt<B::F>, builder: &mut B) {
        builder.push(Instruction::ADDI(value.0, self.0, B::F::zero()));
    }
}

impl<F> fmt::Display for Felt<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "F({})", self.0)
    }
}

impl<F> Add for Felt<F> {
    type Output = Symbolic<F>;

    fn add(self, rhs: Self) -> Symbolic<F> {
        Symbolic::from(self) + rhs
    }
}

impl<F> Add<F> for Felt<F> {
    type Output = Symbolic<F>;

    fn add(self, rhs: F) -> Symbolic<F> {
        Symbolic::from(self) + rhs
    }
}

impl<F> Add<Symbolic<F>> for Felt<F> {
    type Output = Symbolic<F>;

    fn add(self, rhs: Symbolic<F>) -> Symbolic<F> {
        Symbolic::from(self) + rhs
    }
}

impl<F> Sub for Felt<F> {
    type Output = Symbolic<F>;

    fn sub(self, rhs: Self) -> Symbolic<F> {
        Symbolic::from(self) - rhs
    }
}
