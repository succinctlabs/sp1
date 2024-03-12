use core::marker::PhantomData;

use alloc::vec::Vec;
use p3_field::{ExtensionField, Field};

mod builder;
mod ops;
mod symbolic;

pub use builder::*;
pub use ops::*;
pub use symbolic::*;

#[derive(Debug, Clone, Copy)]
pub struct Var<C>(u32, PhantomData<C>);
#[derive(Debug, Clone, Copy)]
pub struct Felt<C>(u32, PhantomData<C>);

#[derive(Debug, Clone, Copy)]

pub struct Ext<C>(u32, PhantomData<C>);

#[derive(Debug, Clone, Copy)]

pub enum Usize<C> {
    Const(usize),
    Var(u32, PhantomData<C>),
}

pub trait Config {
    type N: Field;
    type F: Field;
    type EF: ExtensionField<Self::F>;
}

#[derive(Debug, Clone)]
pub enum DslIR<C: Config> {
    Imm(Var<C>, C::N),
    ImmFelt(Felt<C>, C::F),
    ImmExt(Ext<C>, C::EF),
    AddV(Var<C>, Var<C>, Var<C>),
    AddVI(Var<C>, Var<C>, C::N),
    AddF(Felt<C>, Felt<C>, Felt<C>),
    AddFI(Felt<C>, Felt<C>, C::F),
    AddE(Ext<C>, Ext<C>, Ext<C>),
    AddEI(Ext<C>, Ext<C>, C::EF),
    AddEFI(Ext<C>, Ext<C>, C::F),
    AddEF(Ext<C>, Ext<C>, Felt<C>),
    MulV(Var<C>, Var<C>, Var<C>),
    MulVI(Var<C>, Var<C>, C::N),
    MulF(Felt<C>, Felt<C>, Felt<C>),
    MulFI(Felt<C>, Felt<C>, C::F),
    MulE(Ext<C>, Ext<C>, Ext<C>),
    MulEI(Ext<C>, Ext<C>, C::EF),
    MulEFI(Ext<C>, Ext<C>, C::F),
    MulEF(Ext<C>, Ext<C>, Felt<C>),
    SubV(Var<C>, Var<C>, Var<C>),
    SubVI(Var<C>, Var<C>, C::N),
    SubF(Felt<C>, Felt<C>, Felt<C>),
    SubFI(Felt<C>, Felt<C>, C::F),
    SubE(Ext<C>, Ext<C>, Ext<C>),
    SubEI(Ext<C>, Ext<C>, C::EF),
    SubEFI(Ext<C>, Ext<C>, C::F),
    SubEF(Ext<C>, Ext<C>, Felt<C>),
    DivV(Var<C>, Var<C>, Var<C>),
    DivVI(Var<C>, Var<C>, C::N),
    DivF(Felt<C>, Felt<C>, Felt<C>),
    DivFI(Felt<C>, Felt<C>, C::F),
    DivE(Ext<C>, Ext<C>, Ext<C>),
    DivEI(Ext<C>, Ext<C>, C::EF),
    DivEFI(Ext<C>, Ext<C>, C::F),
    DivEF(Ext<C>, Ext<C>, Felt<C>),
    NegV(Var<C>, Var<C>),
    NegF(Felt<C>, Felt<C>),
    NegE(Ext<C>, Ext<C>),
    InvV(Var<C>, Var<C>),
    InvF(Felt<C>, Felt<C>),
    InvE(Ext<C>, Ext<C>),
    For(Usize<C>, Usize<C>, Vec<DslIR<C>>),
    If(Var<C>, Vec<DslIR<C>>, Vec<DslIR<C>>),
    AssertEqV(Var<C>, Var<C>),
    AssertEqF(Felt<C>, Felt<C>),
    AssertEqE(Ext<C>, Ext<C>),
    AssertEqVI(Var<C>, C::N),
    AssertEqFI(Felt<C>, C::F),
    AssertEqEI(Ext<C>, C::EF),
}
