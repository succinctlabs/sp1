use alloc::vec::Vec;
use p3_field::{ExtensionField, Field};

mod builder;

pub use builder::*;

pub struct Var(u32);

pub struct Felt(u32);

pub struct Ext(u32);

pub enum Usize {
    Const(usize),
    Var(u32),
}

pub trait Config {
    type N: Field;
    type F: Field;
    type EF: ExtensionField<Self::F>;
}

pub trait Variable<C: Config> {
    type Value;
}

pub enum DslIR<C: Config> {
    Imm(Var, C::N),
    ImmFelt(Felt, C::F),
    ImmExt(Ext, C::EF),
    AddV(Var, Var, Var),
    AddVI(Var, Var, C::N),
    AddF(Felt, Felt, Felt),
    AddFI(Felt, Felt, C::F),
    AddE(Ext, Ext, Ext),
    AddEI(Ext, Ext, C::EF),
    AddEFI(Ext, Ext, C::F),
    AddEF(Ext, Ext, Felt),
    MulV(Var, Var, Var),
    MulVI(Var, Var, C::N),
    MulF(Felt, Felt, Felt),
    MulFI(Felt, Felt, C::F),
    MulE(Ext, Ext, Ext),
    MulEI(Ext, Ext, C::EF),
    MulEFI(Ext, Ext, C::F),
    MulEF(Ext, Ext, Felt),
    SubV(Var, Var, Var),
    SubVI(Var, Var, C::N),
    SubF(Felt, Felt, Felt),
    SubFI(Felt, Felt, C::F),
    SubE(Ext, Ext, Ext),
    SubEI(Ext, Ext, C::EF),
    SubEFI(Ext, Ext, C::F),
    SubEF(Ext, Ext, Felt),
    DivV(Var, Var, Var),
    DivVI(Var, Var, C::N),
    DivF(Felt, Felt, Felt),
    DivFI(Felt, Felt, C::F),
    DivE(Ext, Ext, Ext),
    DivEI(Ext, Ext, C::EF),
    DivEFI(Ext, Ext, C::F),
    DivEF(Ext, Ext, Felt),
    NegV(Var, Var),
    NegF(Felt, Felt),
    NegE(Ext, Ext),
    InvV(Var, Var),
    InvF(Felt, Felt),
    InvE(Ext, Ext),
    For(Usize, Usize, Vec<DslIR<C>>),
    If(Var, Vec<DslIR<C>>, Vec<DslIR<C>>),
    AssertEqV(Var, Var),
    AssertEqF(Felt, Felt),
    AssertEqE(Ext, Ext),
    AssertEqVI(Var, C::N),
    AssertEqFI(Felt, C::F),
    AssertEqEI(Ext, C::EF),
}
