use alloc::{format, string::String};

use core::marker::PhantomData;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use serde::{Deserialize, Serialize};

use super::MemVariable;
use super::Ptr;
use super::{Builder, Config, DslIR, SymbolicExt, SymbolicFelt, SymbolicVar, Variable};

#[derive(Debug, Clone, Copy)]
pub struct Var<N>(pub u32, pub PhantomData<N>);

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Felt<F>(pub u32, pub PhantomData<F>);

#[derive(Debug, Clone, Copy)]

pub struct Ext<F, EF>(pub u32, pub PhantomData<(F, EF)>);

#[derive(Debug, Clone, Copy)]

pub enum Usize<N> {
    Const(usize),
    Var(Var<N>),
}

impl<N> Usize<N> {
    pub fn value(&self) -> usize {
        match self {
            Usize::Const(c) => *c,
            Usize::Var(_) => panic!("Cannot get the value of a variable"),
        }
    }
}

impl<N> From<Var<N>> for Usize<N> {
    fn from(v: Var<N>) -> Self {
        Usize::Var(v)
    }
}

impl<N> From<usize> for Usize<N> {
    fn from(c: usize) -> Self {
        Usize::Const(c)
    }
}

impl<N> Var<N> {
    pub fn new(id: u32) -> Self {
        Self(id, PhantomData)
    }

    pub fn id(&self) -> String {
        format!("var{}", self.0)
    }
}

impl<F> Felt<F> {
    pub fn new(id: u32) -> Self {
        Self(id, PhantomData)
    }

    pub fn id(&self) -> String {
        format!("felt{}", self.0)
    }
}

impl<F, EF> Ext<F, EF> {
    pub fn new(id: u32) -> Self {
        Self(id, PhantomData)
    }

    pub fn id(&self) -> String {
        format!("ext{}", self.0)
    }
}

impl<C: Config> Variable<C> for Usize<C::N> {
    type Expression = Self;

    fn uninit(_: &mut Builder<C>) -> Self {
        Usize::Const(0)
    }

    fn assign(&self, src: Self::Expression, builder: &mut Builder<C>) {
        match self {
            Usize::Const(_) => {
                panic!("cannot assign to a constant usize")
            }
            Usize::Var(v) => match src {
                Usize::Const(src) => {
                    builder.assign(*v, C::N::from_canonical_usize(src));
                }
                Usize::Var(src) => {
                    builder.assign(*v, src);
                }
            },
        }
    }

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (lhs, rhs) {
            (Usize::Const(lhs), Usize::Const(rhs)) => {
                assert_eq!(lhs, rhs, "constant usizes do not match");
            }
            (Usize::Const(lhs), Usize::Var(rhs)) => {
                builder.push(DslIR::AssertEqVI(rhs, C::N::from_canonical_usize(lhs)));
            }
            (Usize::Var(lhs), Usize::Const(rhs)) => {
                builder.push(DslIR::AssertEqVI(lhs, C::N::from_canonical_usize(rhs)));
            }
            (Usize::Var(lhs), Usize::Var(rhs)) => {
                builder.push(DslIR::AssertEqV(lhs, rhs));
            }
        }
    }

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (lhs, rhs) {
            (Usize::Const(lhs), Usize::Const(rhs)) => {
                assert_ne!(lhs, rhs, "constant usizes do not match");
            }
            (Usize::Const(lhs), Usize::Var(rhs)) => {
                builder.push(DslIR::AssertNeVI(rhs, C::N::from_canonical_usize(lhs)));
            }
            (Usize::Var(lhs), Usize::Const(rhs)) => {
                builder.push(DslIR::AssertNeVI(lhs, C::N::from_canonical_usize(rhs)));
            }
            (Usize::Var(lhs), Usize::Var(rhs)) => {
                builder.push(DslIR::AssertNeV(lhs, rhs));
            }
        }
    }
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

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (lhs, rhs) {
            (SymbolicVar::Const(lhs), SymbolicVar::Const(rhs)) => {
                assert_eq!(lhs, rhs, "Assertion failed at compile time");
            }
            (SymbolicVar::Const(lhs), SymbolicVar::Val(rhs)) => {
                builder.push(DslIR::AssertEqVI(rhs, lhs));
            }
            (SymbolicVar::Const(lhs), rhs) => {
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.push(DslIR::AssertEqVI(rhs_value, lhs));
            }
            (SymbolicVar::Val(lhs), SymbolicVar::Const(rhs)) => {
                builder.push(DslIR::AssertEqVI(lhs, rhs));
            }
            (SymbolicVar::Val(lhs), SymbolicVar::Val(rhs)) => {
                builder.push(DslIR::AssertEqV(lhs, rhs));
            }
            (SymbolicVar::Val(lhs), rhs) => {
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.push(DslIR::AssertEqV(lhs, rhs_value));
            }
            (lhs, rhs) => {
                let lhs_value = Self::uninit(builder);
                lhs_value.assign(lhs, builder);
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.push(DslIR::AssertEqV(lhs_value, rhs_value));
            }
        }
    }

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (lhs, rhs) {
            (SymbolicVar::Const(lhs), SymbolicVar::Const(rhs)) => {
                assert_ne!(lhs, rhs, "Assertion failed at compile time");
            }
            (SymbolicVar::Const(lhs), SymbolicVar::Val(rhs)) => {
                builder.push(DslIR::AssertNeVI(rhs, lhs));
            }
            (SymbolicVar::Const(lhs), rhs) => {
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.push(DslIR::AssertNeVI(rhs_value, lhs));
            }
            (SymbolicVar::Val(lhs), SymbolicVar::Const(rhs)) => {
                builder.push(DslIR::AssertNeVI(lhs, rhs));
            }
            (SymbolicVar::Val(lhs), SymbolicVar::Val(rhs)) => {
                builder.push(DslIR::AssertNeV(lhs, rhs));
            }
            (SymbolicVar::Val(lhs), rhs) => {
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.push(DslIR::AssertNeV(lhs, rhs_value));
            }
            (lhs, rhs) => {
                let lhs_value = Self::uninit(builder);
                lhs_value.assign(lhs, builder);
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.push(DslIR::AssertNeV(lhs_value, rhs_value));
            }
        }
    }
}

impl<C: Config> MemVariable<C> for Var<C::N> {
    fn size_of() -> usize {
        1
    }

    fn load(&self, ptr: Ptr<C::N>, builder: &mut Builder<C>) {
        builder.push(DslIR::LoadV(*self, ptr));
    }

    fn store(&self, ptr: Ptr<<C as Config>::N>, builder: &mut Builder<C>) {
        builder.push(DslIR::StoreV(ptr, *self));
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

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (lhs, rhs) {
            (SymbolicFelt::Const(lhs), SymbolicFelt::Const(rhs)) => {
                assert_eq!(lhs, rhs, "Assertion failed at compile time");
            }
            (SymbolicFelt::Const(lhs), SymbolicFelt::Val(rhs)) => {
                builder.push(DslIR::AssertEqFI(rhs, lhs));
            }
            (SymbolicFelt::Const(lhs), rhs) => {
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.push(DslIR::AssertEqFI(rhs_value, lhs));
            }
            (SymbolicFelt::Val(lhs), SymbolicFelt::Const(rhs)) => {
                builder.push(DslIR::AssertEqFI(lhs, rhs));
            }
            (SymbolicFelt::Val(lhs), SymbolicFelt::Val(rhs)) => {
                builder.push(DslIR::AssertEqF(lhs, rhs));
            }
            (SymbolicFelt::Val(lhs), rhs) => {
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.push(DslIR::AssertEqF(lhs, rhs_value));
            }
            (lhs, rhs) => {
                let lhs_value = Self::uninit(builder);
                lhs_value.assign(lhs, builder);
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.push(DslIR::AssertEqF(lhs_value, rhs_value));
            }
        }
    }

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (lhs, rhs) {
            (SymbolicFelt::Const(lhs), SymbolicFelt::Const(rhs)) => {
                assert_ne!(lhs, rhs, "Assertion failed at compile time");
            }
            (SymbolicFelt::Const(lhs), SymbolicFelt::Val(rhs)) => {
                builder.push(DslIR::AssertNeFI(rhs, lhs));
            }
            (SymbolicFelt::Const(lhs), rhs) => {
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.push(DslIR::AssertNeFI(rhs_value, lhs));
            }
            (SymbolicFelt::Val(lhs), SymbolicFelt::Const(rhs)) => {
                builder.push(DslIR::AssertNeFI(lhs, rhs));
            }
            (SymbolicFelt::Val(lhs), SymbolicFelt::Val(rhs)) => {
                builder.push(DslIR::AssertNeF(lhs, rhs));
            }
            (SymbolicFelt::Val(lhs), rhs) => {
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.push(DslIR::AssertNeF(lhs, rhs_value));
            }
            (lhs, rhs) => {
                let lhs_value = Self::uninit(builder);
                lhs_value.assign(lhs, builder);
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.push(DslIR::AssertNeF(lhs_value, rhs_value));
            }
        }
    }
}

impl<C: Config> MemVariable<C> for Felt<C::F> {
    fn size_of() -> usize {
        1
    }

    fn load(&self, ptr: Ptr<C::N>, builder: &mut Builder<C>) {
        builder.push(DslIR::LoadF(*self, ptr));
    }

    fn store(&self, ptr: Ptr<<C as Config>::N>, builder: &mut Builder<C>) {
        builder.push(DslIR::StoreF(ptr, *self));
    }
}

impl<C: Config> Variable<C> for Ext<C::F, C::EF> {
    type Expression = SymbolicExt<C::F, C::EF>;

    fn uninit(builder: &mut Builder<C>) -> Self {
        let ext = Ext(builder.ext_count, PhantomData);
        builder.ext_count += 1;
        ext
    }

    fn assign(&self, src: Self::Expression, builder: &mut Builder<C>) {
        match src {
            SymbolicExt::Base(v) => match &*v {
                SymbolicFelt::Const(c) => {
                    builder
                        .operations
                        .push(DslIR::ImmExt(*self, C::EF::from_base(*c)));
                }
                SymbolicFelt::Val(v) => {
                    builder
                        .operations
                        .push(DslIR::AddEFFI(*self, *v, C::EF::zero()));
                }
                v => {
                    let v_value = Felt::uninit(builder);
                    v_value.assign(v.clone(), builder);
                    builder.push(DslIR::AddEFFI(*self, v_value, C::EF::zero()));
                }
            },
            SymbolicExt::Const(c) => {
                builder.operations.push(DslIR::ImmExt(*self, c));
            }
            SymbolicExt::Val(v) => {
                builder
                    .operations
                    .push(DslIR::AddEI(*self, v, C::EF::zero()));
            }
            SymbolicExt::Add(lhs, rhs) => match (&*lhs, &*rhs) {
                (SymbolicExt::Const(lhs), SymbolicExt::Const(rhs)) => {
                    let sum = *lhs + *rhs;
                    builder.operations.push(DslIR::ImmExt(*self, sum));
                }
                (SymbolicExt::Const(lhs), SymbolicExt::Val(rhs)) => {
                    builder.operations.push(DslIR::AddEI(*self, *rhs, *lhs));
                }
                (SymbolicExt::Const(lhs), rhs) => {
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::AddEI(*self, rhs_value, *lhs));
                }
                (SymbolicExt::Val(lhs), SymbolicExt::Const(rhs)) => {
                    builder.push(DslIR::AddEI(*self, *lhs, *rhs));
                }
                (SymbolicExt::Val(lhs), SymbolicExt::Val(rhs)) => {
                    builder.push(DslIR::AddE(*self, *lhs, *rhs));
                }
                (SymbolicExt::Val(lhs), rhs) => {
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::AddE(*self, *lhs, rhs_value));
                }
                (lhs, SymbolicExt::Const(rhs)) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    builder.push(DslIR::AddEI(*self, lhs_value, *rhs));
                }
                (lhs, SymbolicExt::Val(rhs)) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    builder.push(DslIR::AddE(*self, lhs_value, *rhs));
                }
                (lhs, rhs) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::AddE(*self, lhs_value, rhs_value));
                }
            },
            SymbolicExt::Mul(lhs, rhs) => match (&*lhs, &*rhs) {
                (SymbolicExt::Const(lhs), SymbolicExt::Const(rhs)) => {
                    let product = *lhs * *rhs;
                    builder.push(DslIR::ImmExt(*self, product));
                }
                (SymbolicExt::Const(lhs), SymbolicExt::Val(rhs)) => {
                    builder.push(DslIR::MulEI(*self, *rhs, *lhs));
                }
                (SymbolicExt::Const(lhs), rhs) => {
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::MulEI(*self, rhs_value, *lhs));
                }
                (SymbolicExt::Val(lhs), SymbolicExt::Const(rhs)) => {
                    builder.push(DslIR::MulEI(*self, *lhs, *rhs));
                }
                (SymbolicExt::Val(lhs), SymbolicExt::Val(rhs)) => {
                    builder.push(DslIR::MulE(*self, *lhs, *rhs));
                }
                (SymbolicExt::Val(lhs), rhs) => {
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::MulE(*self, *lhs, rhs_value));
                }
                (lhs, SymbolicExt::Const(rhs)) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    builder.push(DslIR::MulEI(*self, lhs_value, *rhs));
                }
                (lhs, SymbolicExt::Val(rhs)) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    builder.push(DslIR::MulE(*self, lhs_value, *rhs));
                }
                (lhs, rhs) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::MulE(*self, lhs_value, rhs_value));
                }
            },
            SymbolicExt::Sub(lhs, rhs) => match (&*lhs, &*rhs) {
                (SymbolicExt::Const(lhs), SymbolicExt::Const(rhs)) => {
                    let difference = *lhs - *rhs;
                    builder.push(DslIR::ImmExt(*self, difference));
                }
                (SymbolicExt::Const(lhs), SymbolicExt::Val(rhs)) => {
                    builder.push(DslIR::SubEIN(*self, *lhs, *rhs));
                }
                (SymbolicExt::Const(lhs), rhs) => {
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::SubEIN(*self, *lhs, rhs_value));
                }
                (SymbolicExt::Val(lhs), SymbolicExt::Const(rhs)) => {
                    builder.push(DslIR::SubEI(*self, *lhs, *rhs));
                }
                (SymbolicExt::Val(lhs), SymbolicExt::Val(rhs)) => {
                    builder.push(DslIR::SubE(*self, *lhs, *rhs));
                }
                (SymbolicExt::Val(lhs), rhs) => {
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::SubE(*self, *lhs, rhs_value));
                }
                (lhs, SymbolicExt::Const(rhs)) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    builder.push(DslIR::SubEI(*self, lhs_value, *rhs));
                }
                (lhs, SymbolicExt::Val(rhs)) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    builder.push(DslIR::SubE(*self, lhs_value, *rhs));
                }
                (lhs, rhs) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::SubE(*self, lhs_value, rhs_value));
                }
            },
            SymbolicExt::Div(lhs, rhs) => match (&*lhs, &*rhs) {
                (SymbolicExt::Const(lhs), SymbolicExt::Const(rhs)) => {
                    let quotient = *lhs / *rhs;
                    builder.push(DslIR::ImmExt(*self, quotient));
                }
                (SymbolicExt::Const(lhs), SymbolicExt::Val(rhs)) => {
                    builder.push(DslIR::DivEIN(*self, *lhs, *rhs));
                }
                (SymbolicExt::Const(lhs), rhs) => {
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::DivEIN(*self, *lhs, rhs_value));
                }
                (SymbolicExt::Val(lhs), SymbolicExt::Const(rhs)) => {
                    builder.push(DslIR::DivEI(*self, *lhs, *rhs));
                }
                (SymbolicExt::Val(lhs), SymbolicExt::Val(rhs)) => {
                    builder.push(DslIR::DivE(*self, *lhs, *rhs));
                }
                (SymbolicExt::Val(lhs), rhs) => {
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::DivE(*self, *lhs, rhs_value));
                }
                (lhs, SymbolicExt::Const(rhs)) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    builder.push(DslIR::DivEI(*self, lhs_value, *rhs));
                }
                (lhs, SymbolicExt::Val(rhs)) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    builder.push(DslIR::DivE(*self, lhs_value, *rhs));
                }
                (lhs, rhs) => {
                    let lhs_value = Self::uninit(builder);
                    lhs_value.assign(lhs.clone(), builder);
                    let rhs_value = Self::uninit(builder);
                    rhs_value.assign(rhs.clone(), builder);
                    builder.push(DslIR::DivE(*self, lhs_value, rhs_value));
                }
            },
            SymbolicExt::Neg(operand) => match &*operand {
                SymbolicExt::Const(operand) => {
                    let negated = -*operand;
                    builder.push(DslIR::ImmExt(*self, negated));
                }
                SymbolicExt::Val(operand) => {
                    builder.push(DslIR::SubEFIN(*self, C::F::zero(), *operand));
                }
                operand => {
                    let operand_value = Self::uninit(builder);
                    operand_value.assign(operand.clone(), builder);
                    builder.push(DslIR::SubEFIN(*self, C::F::zero(), operand_value));
                }
            },
        }
    }

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (lhs, rhs) {
            (SymbolicExt::Const(lhs), SymbolicExt::Const(rhs)) => {
                assert_eq!(lhs, rhs, "Assertion failed at compile time");
            }
            (SymbolicExt::Const(lhs), SymbolicExt::Val(rhs)) => {
                builder.push(DslIR::AssertEqEI(rhs, lhs));
            }
            (SymbolicExt::Const(lhs), rhs) => {
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.push(DslIR::AssertEqEI(rhs_value, lhs));
            }
            (SymbolicExt::Val(lhs), SymbolicExt::Const(rhs)) => {
                builder.push(DslIR::AssertEqEI(lhs, rhs));
            }
            (SymbolicExt::Val(lhs), SymbolicExt::Val(rhs)) => {
                builder.push(DslIR::AssertEqE(lhs, rhs));
            }
            (SymbolicExt::Val(lhs), rhs) => {
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.push(DslIR::AssertEqE(lhs, rhs_value));
            }
            (lhs, rhs) => {
                let lhs_value = Self::uninit(builder);
                lhs_value.assign(lhs, builder);
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.push(DslIR::AssertEqE(lhs_value, rhs_value));
            }
        }
    }

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<C>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (lhs, rhs) {
            (SymbolicExt::Const(lhs), SymbolicExt::Const(rhs)) => {
                assert_ne!(lhs, rhs, "Assertion failed at compile time");
            }
            (SymbolicExt::Const(lhs), SymbolicExt::Val(rhs)) => {
                builder.push(DslIR::AssertNeEI(rhs, lhs));
            }
            (SymbolicExt::Const(lhs), rhs) => {
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.push(DslIR::AssertNeEI(rhs_value, lhs));
            }
            (SymbolicExt::Val(lhs), SymbolicExt::Const(rhs)) => {
                builder.push(DslIR::AssertNeEI(lhs, rhs));
            }
            (SymbolicExt::Val(lhs), SymbolicExt::Val(rhs)) => {
                builder.push(DslIR::AssertNeE(lhs, rhs));
            }
            (SymbolicExt::Val(lhs), rhs) => {
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.push(DslIR::AssertNeE(lhs, rhs_value));
            }
            (lhs, rhs) => {
                let lhs_value = Self::uninit(builder);
                lhs_value.assign(lhs, builder);
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.push(DslIR::AssertNeE(lhs_value, rhs_value));
            }
        }
    }
}

impl<C: Config> MemVariable<C> for Ext<C::F, C::EF> {
    fn size_of() -> usize {
        4
    }

    fn load(&self, ptr: Ptr<C::N>, builder: &mut Builder<C>) {
        builder.push(DslIR::LoadE(*self, ptr));
    }

    fn store(&self, ptr: Ptr<<C as Config>::N>, builder: &mut Builder<C>) {
        builder.push(DslIR::StoreE(ptr, *self));
    }
}
