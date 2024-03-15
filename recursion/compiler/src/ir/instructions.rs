use super::{BinomialExtension, Ptr};

use super::{Config, Ext, Felt, Usize, Var};

#[derive(Debug, Clone)]
pub enum DslIR<C: Config> {
    Imm(Var<C::N>, C::N),
    ImmFelt(Felt<C::F>, C::F),
    ImmExt(Ext<C::F>, BinomialExtension<C::F>),

    // Arithmetic instructions.
    AddV(Var<C::N>, Var<C::N>, Var<C::N>),
    AddVI(Var<C::N>, Var<C::N>, C::N),
    AddF(Felt<C::F>, Felt<C::F>, Felt<C::F>),
    AddFI(Felt<C::F>, Felt<C::F>, C::F),
    AddE(Ext<C::F>, Ext<C::F>, Ext<C::F>),
    AddEI(Ext<C::F>, Ext<C::F>, BinomialExtension<C::F>),
    AddEFI(Ext<C::F>, Ext<C::F>, C::F),
    AddEFFI(Ext<C::F>, Felt<C::F>, BinomialExtension<C::F>),
    AddEF(Ext<C::F>, Ext<C::F>, Felt<C::F>),
    MulV(Var<C::N>, Var<C::N>, Var<C::N>),
    MulVI(Var<C::N>, Var<C::N>, C::N),
    MulF(Felt<C::F>, Felt<C::F>, Felt<C::F>),
    MulFI(Felt<C::F>, Felt<C::F>, C::F),
    MulE(Ext<C::F>, Ext<C::F>, Ext<C::F>),
    MulEI(Ext<C::F>, Ext<C::F>, BinomialExtension<C::F>),
    MulEFI(Ext<C::F>, Ext<C::F>, C::F),
    MulEF(Ext<C::F>, Ext<C::F>, Felt<C::F>),
    SubV(Var<C::N>, Var<C::N>, Var<C::N>),
    SubVI(Var<C::N>, Var<C::N>, C::N),
    SubVIN(Var<C::N>, C::N, Var<C::N>),
    SubF(Felt<C::F>, Felt<C::F>, Felt<C::F>),
    SubFI(Felt<C::F>, Felt<C::F>, C::F),
    SubFIN(Felt<C::F>, C::F, Felt<C::F>),
    SubE(Ext<C::F>, Ext<C::F>, Ext<C::F>),
    SubEI(Ext<C::F>, Ext<C::F>, BinomialExtension<C::F>),
    SubEIN(Ext<C::F>, BinomialExtension<C::F>, Ext<C::F>),
    SubEFI(Ext<C::F>, Ext<C::F>, C::F),
    SubEFIN(Ext<C::F>, C::F, Ext<C::F>),
    SubEF(Ext<C::F>, Ext<C::F>, Felt<C::F>),
    DivF(Felt<C::F>, Felt<C::F>, Felt<C::F>),
    DivFI(Felt<C::F>, Felt<C::F>, C::F),
    DivFIN(Felt<C::F>, C::F, Felt<C::F>),
    DivE(Ext<C::F>, Ext<C::F>, Ext<C::F>),
    DivEI(Ext<C::F>, Ext<C::F>, BinomialExtension<C::F>),
    DivEIN(Ext<C::F>, BinomialExtension<C::F>, Ext<C::F>),
    DivEFI(Ext<C::F>, Ext<C::F>, C::F),
    DivEFIN(Ext<C::F>, C::F, Ext<C::F>),
    DivEF(Ext<C::F>, Ext<C::F>, Felt<C::F>),
    NegV(Var<C::N>, Var<C::N>),
    NegF(Felt<C::F>, Felt<C::F>),
    NegE(Ext<C::F>, Ext<C::F>),
    InvV(Var<C::N>, Var<C::N>),
    InvF(Felt<C::F>, Felt<C::F>),
    InvE(Ext<C::F>, Ext<C::F>),
    For(Usize<C::N>, Usize<C::N>, Var<C::N>, Vec<DslIR<C>>),
    IfEq(Var<C::N>, Var<C::N>, Vec<DslIR<C>>, Vec<DslIR<C>>),
    IfNe(Var<C::N>, Var<C::N>, Vec<DslIR<C>>, Vec<DslIR<C>>),
    IfEqI(Var<C::N>, C::N, Vec<DslIR<C>>, Vec<DslIR<C>>),
    IfNeI(Var<C::N>, C::N, Vec<DslIR<C>>, Vec<DslIR<C>>),
    AssertEqV(Var<C::N>, Var<C::N>),
    AssertNeV(Var<C::N>, Var<C::N>),
    AssertEqF(Felt<C::F>, Felt<C::F>),
    AssertNeF(Felt<C::F>, Felt<C::F>),
    AssertEqE(Ext<C::F>, Ext<C::F>),
    AssertNeE(Ext<C::F>, Ext<C::F>),
    AssertEqVI(Var<C::N>, C::N),
    AssertNeVI(Var<C::N>, C::N),
    AssertEqFI(Felt<C::F>, C::F),
    AssertNeFI(Felt<C::F>, C::F),
    AssertEqEI(Ext<C::F>, BinomialExtension<C::F>),
    AssertNeEI(Ext<C::F>, BinomialExtension<C::F>),
    // Memory instructions.
    /// Allocate (ptr, len, size) allocated a memory slice of length `len * size`
    Alloc(Ptr<C::N>, Usize<C::N>, usize),
    /// Load variable (var, ptr, offset)
    LoadV(Var<C::N>, Ptr<C::N>, Usize<C::N>),
    /// Load field element (var, ptr, offset)
    LoadF(Felt<C::F>, Ptr<C::N>, Usize<C::N>),
    /// Load extension field
    LoadE(Ext<C::F>, Ptr<C::N>, Usize<C::N>),
    /// Store variable
    StoreV(Var<C::N>, Ptr<C::N>, Usize<C::N>),
    /// Store field element
    StoreF(Felt<C::F>, Ptr<C::N>, Usize<C::N>),
    /// Store extension field
    StoreE(Ext<C::F>, Ptr<C::N>, Usize<C::N>),
}
