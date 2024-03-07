use crate::asm::Instruction;
use crate::ir::Builder;
use crate::ir::FromConstant;
use crate::ir::SizedVariable;
use crate::ir::Variable;
use core::fmt;

pub const ZERO: F = F(0);
pub const ONE: F = F(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct F(u32);

impl<B: Builder> Variable<B> for F {
    fn uninit(builder: &mut B) -> Self {
        F(builder.get_mem(1))
    }
}

impl<B: Builder> SizedVariable<B> for F {
    fn size_of() -> usize {
        1
    }
}

impl<B: Builder> FromConstant<B> for F {
    type Constant = u32;

    fn constant(builder: &mut B, value: Self::Constant) -> Self {
        let var = Self::uninit(builder);
        builder.push(Instruction::ADDI(var, ZERO, value));
        var
    }
}

impl fmt::Display for F {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "F({})", self.0)
    }
}
