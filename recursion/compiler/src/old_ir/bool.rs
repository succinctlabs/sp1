use super::Builder;
use super::Constant;
use super::Expression;
use super::SizedVariable;
use super::SymbolicLogic;
use super::Variable;
use crate::asm::AsmInstruction;
use core::ops::{BitAnd, BitOr, BitXor, Not};
use p3_field::AbstractField;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bool(pub i32);

impl<B: Builder> Variable<B> for Bool {
    fn uninit(builder: &mut B) -> Self {
        Bool(builder.get_mem(4))
    }
}

impl<B: Builder> SizedVariable<B> for Bool {
    fn size_of() -> usize {
        1
    }
}

impl<B: Builder> Constant<B> for Bool {
    type Constant = bool;

    fn imm(&self, constant: Self::Constant, builder: &mut B) {
        builder.push(AsmInstruction::IMM(self.0, B::F::from_bool(constant)));
    }
}

impl<B: Builder> Expression<B> for Bool {
    type Value = Bool;

    fn assign(&self, value: Bool, builder: &mut B) {
        builder.push(AsmInstruction::ADDI(value.0, self.0, B::F::zero()));
    }
}

impl BitAnd for Bool {
    type Output = SymbolicLogic;

    fn bitand(self, rhs: Self) -> SymbolicLogic {
        SymbolicLogic::from(self) & rhs
    }
}

impl BitAnd<SymbolicLogic> for Bool {
    type Output = SymbolicLogic;

    fn bitand(self, rhs: SymbolicLogic) -> SymbolicLogic {
        SymbolicLogic::from(self) & rhs
    }
}

impl BitAnd<bool> for Bool {
    type Output = SymbolicLogic;

    fn bitand(self, rhs: bool) -> SymbolicLogic {
        SymbolicLogic::from(self) & rhs
    }
}

impl BitOr for Bool {
    type Output = SymbolicLogic;

    fn bitor(self, rhs: Self) -> SymbolicLogic {
        SymbolicLogic::from(self) | rhs
    }
}

impl BitOr<SymbolicLogic> for Bool {
    type Output = SymbolicLogic;

    fn bitor(self, rhs: SymbolicLogic) -> SymbolicLogic {
        SymbolicLogic::from(self) | rhs
    }
}

impl BitOr<bool> for Bool {
    type Output = SymbolicLogic;

    fn bitor(self, rhs: bool) -> SymbolicLogic {
        SymbolicLogic::from(self) | rhs
    }
}

impl BitXor for Bool {
    type Output = SymbolicLogic;

    fn bitxor(self, rhs: Self) -> SymbolicLogic {
        SymbolicLogic::from(self) ^ rhs
    }
}

impl BitXor<SymbolicLogic> for Bool {
    type Output = SymbolicLogic;

    fn bitxor(self, rhs: SymbolicLogic) -> SymbolicLogic {
        SymbolicLogic::from(self) ^ rhs
    }
}

impl BitXor<bool> for Bool {
    type Output = SymbolicLogic;

    fn bitxor(self, rhs: bool) -> SymbolicLogic {
        SymbolicLogic::from(self) ^ rhs
    }
}

impl Not for Bool {
    type Output = SymbolicLogic;

    fn not(self) -> SymbolicLogic {
        !SymbolicLogic::from(self)
    }
}
