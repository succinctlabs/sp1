use super::DslIR;
use super::{SymbolicExt, SymbolicFelt, SymbolicVar};
use core::marker::PhantomData;
use p3_field::AbstractField;

use super::{Builder, Config, Ext, Felt, Var};
pub trait Variable<C: Config> {
    type Expression;

    fn uninit(builder: &mut Builder<C>) -> Self;

    fn assign(&self, src: Self::Expression, builder: &mut Builder<C>);
}

pub trait Equal<C: Config, Rhs = Self> {
    fn assert_equal(&self, rhs: &Rhs, builder: &mut Builder<C>);
}

impl<C: Config> Variable<C> for Var<C::N> {
    type Expression = SymbolicVar<C::N>;

    fn uninit(builder: &mut Builder<C>) -> Self {
        let var = Var(builder.var_count, PhantomData);
        builder.var_count += 1;
        var
    }

    fn assign(&self, src: Self::Expression, builder: &mut Builder<C>) {
        match src {
            SymbolicVar::Const(c) => {
                builder.operations.push(DslIR::Imm(*self, c));
            }
            SymbolicVar::Val(v) => {
                builder
                    .operations
                    .push(DslIR::AddVI(*self, v, C::N::zero()));
            }
            SymbolicVar::Add(lhs, rhs) => match (&*lhs, &*rhs) {
                (SymbolicVar::Const(lhs), SymbolicVar::Const(rhs)) => {
                    let sum = *lhs + *rhs;
                    builder.operations.push(DslIR::Imm(*self, sum));
                }
                (SymbolicVar::Const(lhs), SymbolicVar::Val(rhs)) => {
                    builder.operations.push(DslIR::AddVI(*self, *rhs, *lhs));
                }
                (SymbolicVar::Const(lhs), rhs) => {
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::AddVI(*self, rhs_value, *lhs));
                }
                (SymbolicVar::Val(lhs), SymbolicVar::Const(rhs)) => {
                    builder.push(DslIR::AddVI(*self, *lhs, *rhs));
                }
                (SymbolicVar::Val(lhs), SymbolicVar::Val(rhs)) => {
                    builder.push(DslIR::AddV(*self, *lhs, *rhs));
                }
                (SymbolicVar::Val(lhs), rhs) => {
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::AddV(*self, *lhs, rhs_value));
                }
                (lhs, SymbolicVar::Const(rhs)) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    builder.push(DslIR::AddVI(*self, lhs_value, *rhs));
                }
                (lhs, SymbolicVar::Val(rhs)) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    builder.push(DslIR::AddV(*self, lhs_value, *rhs));
                }
                (lhs, rhs) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::AddV(*self, lhs_value, rhs_value));
                }
            },
            SymbolicVar::Mul(lhs, rhs) => match (&*lhs, &*rhs) {
                (SymbolicVar::Const(lhs), SymbolicVar::Const(rhs)) => {
                    let product = *lhs * *rhs;
                    builder.push(DslIR::Imm(*self, product));
                }
                (SymbolicVar::Const(lhs), SymbolicVar::Val(rhs)) => {
                    builder.push(DslIR::MulVI(*self, *rhs, *lhs));
                }
                (SymbolicVar::Const(lhs), rhs) => {
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::MulVI(*self, rhs_value, *lhs));
                }
                (SymbolicVar::Val(lhs), SymbolicVar::Const(rhs)) => {
                    builder.push(DslIR::MulVI(*self, *lhs, *rhs));
                }
                (SymbolicVar::Val(lhs), SymbolicVar::Val(rhs)) => {
                    builder.push(DslIR::MulV(*self, *lhs, *rhs));
                }
                (SymbolicVar::Val(lhs), rhs) => {
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::MulV(*self, *lhs, rhs_value));
                }
                (lhs, SymbolicVar::Const(rhs)) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    builder.push(DslIR::MulVI(*self, lhs_value, *rhs));
                }
                (lhs, SymbolicVar::Val(rhs)) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    builder.push(DslIR::MulV(*self, lhs_value, *rhs));
                }
                (lhs, rhs) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::MulV(*self, lhs_value, rhs_value));
                }
            },
            SymbolicVar::Sub(lhs, rhs) => match (&*lhs, &*rhs) {
                (SymbolicVar::Const(lhs), SymbolicVar::Const(rhs)) => {
                    let difference = *lhs - *rhs;
                    builder.push(DslIR::Imm(*self, difference));
                }
                (SymbolicVar::Const(lhs), SymbolicVar::Val(rhs)) => {
                    builder.push(DslIR::SubVIN(*self, *lhs, *rhs));
                }
                (SymbolicVar::Const(lhs), rhs) => {
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::SubVIN(*self, *lhs, rhs_value));
                }
                (SymbolicVar::Val(lhs), SymbolicVar::Const(rhs)) => {
                    builder.push(DslIR::SubVI(*self, *lhs, *rhs));
                }
                (SymbolicVar::Val(lhs), SymbolicVar::Val(rhs)) => {
                    builder.push(DslIR::SubV(*self, *lhs, *rhs));
                }
                (SymbolicVar::Val(lhs), rhs) => {
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::SubV(*self, *lhs, rhs_value));
                }
                (lhs, SymbolicVar::Const(rhs)) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    builder.push(DslIR::SubVI(*self, lhs_value, *rhs));
                }
                (lhs, SymbolicVar::Val(rhs)) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    builder.push(DslIR::SubV(*self, lhs_value, *rhs));
                }
                (lhs, rhs) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::SubV(*self, lhs_value, rhs_value));
                }
            },
            SymbolicVar::Neg(operand) => match &*operand {
                SymbolicVar::Const(operand) => {
                    let negated = -*operand;
                    builder.push(DslIR::Imm(*self, negated));
                }
                SymbolicVar::Val(operand) => {
                    builder.push(DslIR::SubVIN(*self, C::N::zero(), *operand));
                }
                operand => {
                    let operand_value = Self::uninit(builder);
                    operand_value.assign(operand.clone(), builder);
                    builder.push(DslIR::SubVIN(*self, C::N::zero(), operand_value));
                }
            },
        }
    }
}

impl<C: Config> Variable<C> for Felt<C::F> {
    type Expression = SymbolicFelt<C::F>;

    fn uninit(builder: &mut Builder<C>) -> Self {
        let felt = Felt(builder.felt_count, PhantomData);
        builder.felt_count += 1;
        felt
    }

    fn assign(&self, src: Self::Expression, builder: &mut Builder<C>) {
        match src {
            SymbolicFelt::Const(c) => {
                builder.operations.push(DslIR::ImmFelt(*self, c));
            }
            SymbolicFelt::Val(v) => {
                builder
                    .operations
                    .push(DslIR::AddFI(*self, v, C::F::zero()));
            }
            SymbolicFelt::Add(lhs, rhs) => match (&*lhs, &*rhs) {
                (SymbolicFelt::Const(lhs), SymbolicFelt::Const(rhs)) => {
                    let sum = *lhs + *rhs;
                    builder.operations.push(DslIR::ImmFelt(*self, sum));
                }
                (SymbolicFelt::Const(lhs), SymbolicFelt::Val(rhs)) => {
                    builder.operations.push(DslIR::AddFI(*self, *rhs, *lhs));
                }
                (SymbolicFelt::Const(lhs), rhs) => {
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::AddFI(*self, rhs_value, *lhs));
                }
                (SymbolicFelt::Val(lhs), SymbolicFelt::Const(rhs)) => {
                    builder.push(DslIR::AddFI(*self, *lhs, *rhs));
                }
                (SymbolicFelt::Val(lhs), SymbolicFelt::Val(rhs)) => {
                    builder.push(DslIR::AddF(*self, *lhs, *rhs));
                }
                (SymbolicFelt::Val(lhs), rhs) => {
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::AddF(*self, *lhs, rhs_value));
                }
                (lhs, SymbolicFelt::Const(rhs)) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    builder.push(DslIR::AddFI(*self, lhs_value, *rhs));
                }
                (lhs, SymbolicFelt::Val(rhs)) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    builder.push(DslIR::AddF(*self, lhs_value, *rhs));
                }
                (lhs, rhs) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::AddF(*self, lhs_value, rhs_value));
                }
            },
            SymbolicFelt::Mul(lhs, rhs) => match (&*lhs, &*rhs) {
                (SymbolicFelt::Const(lhs), SymbolicFelt::Const(rhs)) => {
                    let product = *lhs * *rhs;
                    builder.push(DslIR::ImmFelt(*self, product));
                }
                (SymbolicFelt::Const(lhs), SymbolicFelt::Val(rhs)) => {
                    builder.push(DslIR::MulFI(*self, *rhs, *lhs));
                }
                (SymbolicFelt::Const(lhs), rhs) => {
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::MulFI(*self, rhs_value, *lhs));
                }
                (SymbolicFelt::Val(lhs), SymbolicFelt::Const(rhs)) => {
                    builder.push(DslIR::MulFI(*self, *lhs, *rhs));
                }
                (SymbolicFelt::Val(lhs), SymbolicFelt::Val(rhs)) => {
                    builder.push(DslIR::MulF(*self, *lhs, *rhs));
                }
                (SymbolicFelt::Val(lhs), rhs) => {
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::MulF(*self, *lhs, rhs_value));
                }
                (lhs, SymbolicFelt::Const(rhs)) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    builder.push(DslIR::MulFI(*self, lhs_value, *rhs));
                }
                (lhs, SymbolicFelt::Val(rhs)) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    builder.push(DslIR::MulF(*self, lhs_value, *rhs));
                }
                (lhs, rhs) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::MulF(*self, lhs_value, rhs_value));
                }
            },
            SymbolicFelt::Sub(lhs, rhs) => match (&*lhs, &*rhs) {
                (SymbolicFelt::Const(lhs), SymbolicFelt::Const(rhs)) => {
                    let difference = *lhs - *rhs;
                    builder.push(DslIR::ImmFelt(*self, difference));
                }
                (SymbolicFelt::Const(lhs), SymbolicFelt::Val(rhs)) => {
                    builder.push(DslIR::SubFIN(*self, *lhs, *rhs));
                }
                (SymbolicFelt::Const(lhs), rhs) => {
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::SubFIN(*self, *lhs, rhs_value));
                }
                (SymbolicFelt::Val(lhs), SymbolicFelt::Const(rhs)) => {
                    builder.push(DslIR::SubFI(*self, *lhs, *rhs));
                }
                (SymbolicFelt::Val(lhs), SymbolicFelt::Val(rhs)) => {
                    builder.push(DslIR::SubF(*self, *lhs, *rhs));
                }
                (SymbolicFelt::Val(lhs), rhs) => {
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::SubF(*self, *lhs, rhs_value));
                }
                (lhs, SymbolicFelt::Const(rhs)) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    builder.push(DslIR::SubFI(*self, lhs_value, *rhs));
                }
                (lhs, SymbolicFelt::Val(rhs)) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    builder.push(DslIR::SubF(*self, lhs_value, *rhs));
                }
                (lhs, rhs) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::SubF(*self, lhs_value, rhs_value));
                }
            },
            SymbolicFelt::Div(lhs, rhs) => match (&*lhs, &*rhs) {
                (SymbolicFelt::Const(lhs), SymbolicFelt::Const(rhs)) => {
                    let quotient = *lhs / *rhs;
                    builder.push(DslIR::ImmFelt(*self, quotient));
                }
                (SymbolicFelt::Const(lhs), SymbolicFelt::Val(rhs)) => {
                    builder.push(DslIR::DivFIN(*self, *lhs, *rhs));
                }
                (SymbolicFelt::Const(lhs), rhs) => {
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::DivFIN(*self, *lhs, rhs_value));
                }
                (SymbolicFelt::Val(lhs), SymbolicFelt::Const(rhs)) => {
                    builder.push(DslIR::DivFI(*self, *lhs, *rhs));
                }
                (SymbolicFelt::Val(lhs), SymbolicFelt::Val(rhs)) => {
                    builder.push(DslIR::DivF(*self, *lhs, *rhs));
                }
                (SymbolicFelt::Val(lhs), rhs) => {
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::DivF(*self, *lhs, rhs_value));
                }
                (lhs, SymbolicFelt::Const(rhs)) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    builder.push(DslIR::DivFI(*self, lhs_value, *rhs));
                }
                (lhs, SymbolicFelt::Val(rhs)) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    builder.push(DslIR::DivF(*self, lhs_value, *rhs));
                }
                (lhs, rhs) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::DivF(*self, lhs_value, rhs_value));
                }
            },
            SymbolicFelt::Neg(operand) => match &*operand {
                SymbolicFelt::Const(operand) => {
                    let negated = -*operand;
                    builder.push(DslIR::ImmFelt(*self, negated));
                }
                SymbolicFelt::Val(operand) => {
                    builder.push(DslIR::SubFIN(*self, C::F::zero(), *operand));
                }
                operand => {
                    let operand_value = Self::uninit(builder);
                    operand_value.assign(operand.clone(), builder);
                    builder.push(DslIR::SubFIN(*self, C::F::zero(), operand_value));
                }
            },
        }
    }
}
