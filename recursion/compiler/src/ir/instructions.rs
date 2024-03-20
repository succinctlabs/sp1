use super::{Array, Ptr};

use super::{Config, Ext, Felt, Usize, Var};

#[derive(Debug, Clone)]
pub enum DslIR<C: Config> {
    Imm(Var<C::N>, C::N),
    ImmFelt(Felt<C::F>, C::F),
    ImmExt(Ext<C::F, C::EF>, C::EF),

    // Arithmetic instructions.
    AddV(Var<C::N>, Var<C::N>, Var<C::N>),
    AddVI(Var<C::N>, Var<C::N>, C::N),
    AddF(Felt<C::F>, Felt<C::F>, Felt<C::F>),
    AddFI(Felt<C::F>, Felt<C::F>, C::F),
    AddE(Ext<C::F, C::EF>, Ext<C::F, C::EF>, Ext<C::F, C::EF>),
    AddEI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::EF),
    AddEFI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::F),
    AddEFFI(Ext<C::F, C::EF>, Felt<C::F>, C::EF),
    AddEF(Ext<C::F, C::EF>, Ext<C::F, C::EF>, Felt<C::F>),
    MulV(Var<C::N>, Var<C::N>, Var<C::N>),
    MulVI(Var<C::N>, Var<C::N>, C::N),
    MulF(Felt<C::F>, Felt<C::F>, Felt<C::F>),
    MulFI(Felt<C::F>, Felt<C::F>, C::F),
    MulE(Ext<C::F, C::EF>, Ext<C::F, C::EF>, Ext<C::F, C::EF>),
    MulEI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::EF),
    MulEFI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::F),
    MulEF(Ext<C::F, C::EF>, Ext<C::F, C::EF>, Felt<C::F>),
    SubV(Var<C::N>, Var<C::N>, Var<C::N>),
    SubVI(Var<C::N>, Var<C::N>, C::N),
    SubVIN(Var<C::N>, C::N, Var<C::N>),
    SubF(Felt<C::F>, Felt<C::F>, Felt<C::F>),
    SubFI(Felt<C::F>, Felt<C::F>, C::F),
    SubFIN(Felt<C::F>, C::F, Felt<C::F>),
    SubE(Ext<C::F, C::EF>, Ext<C::F, C::EF>, Ext<C::F, C::EF>),
    SubEI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::EF),
    SubEIN(Ext<C::F, C::EF>, C::EF, Ext<C::F, C::EF>),
    SubEFI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::F),
    SubEFIN(Ext<C::F, C::EF>, C::F, Ext<C::F, C::EF>),
    SubEF(Ext<C::F, C::EF>, Ext<C::F, C::EF>, Felt<C::F>),
    DivF(Felt<C::F>, Felt<C::F>, Felt<C::F>),
    DivFI(Felt<C::F>, Felt<C::F>, C::F),
    DivFIN(Felt<C::F>, C::F, Felt<C::F>),
    DivE(Ext<C::F, C::EF>, Ext<C::F, C::EF>, Ext<C::F, C::EF>),
    DivEI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::EF),
    DivEIN(Ext<C::F, C::EF>, C::EF, Ext<C::F, C::EF>),
    DivEFI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::F),
    DivEFIN(Ext<C::F, C::EF>, C::F, Ext<C::F, C::EF>),
    DivEF(Ext<C::F, C::EF>, Ext<C::F, C::EF>, Felt<C::F>),
    NegV(Var<C::N>, Var<C::N>),
    NegF(Felt<C::F>, Felt<C::F>),
    NegE(Ext<C::F, C::EF>, Ext<C::F, C::EF>),
    InvV(Var<C::N>, Var<C::N>),
    InvF(Felt<C::F>, Felt<C::F>),
    InvE(Ext<C::F, C::EF>, Ext<C::F, C::EF>),
    For(Usize<C::N>, Usize<C::N>, Var<C::N>, Vec<DslIR<C>>),
    IfEq(Var<C::N>, Var<C::N>, Vec<DslIR<C>>, Vec<DslIR<C>>),
    IfNe(Var<C::N>, Var<C::N>, Vec<DslIR<C>>, Vec<DslIR<C>>),
    IfEqI(Var<C::N>, C::N, Vec<DslIR<C>>, Vec<DslIR<C>>),
    IfNeI(Var<C::N>, C::N, Vec<DslIR<C>>, Vec<DslIR<C>>),
    AssertEqV(Var<C::N>, Var<C::N>),
    AssertNeV(Var<C::N>, Var<C::N>),
    AssertEqF(Felt<C::F>, Felt<C::F>),
    AssertNeF(Felt<C::F>, Felt<C::F>),
    AssertEqE(Ext<C::F, C::EF>, Ext<C::F, C::EF>),
    AssertNeE(Ext<C::F, C::EF>, Ext<C::F, C::EF>),
    AssertEqVI(Var<C::N>, C::N),
    AssertNeVI(Var<C::N>, C::N),
    AssertEqFI(Felt<C::F>, C::F),
    AssertNeFI(Felt<C::F>, C::F),
    AssertEqEI(Ext<C::F, C::EF>, C::EF),
    AssertNeEI(Ext<C::F, C::EF>, C::EF),

    // Memory instructions.
    /// Allocate (ptr, len) a memory slice of length len
    Alloc(Ptr<C::N>, Usize<C::N>),
    /// Load variable (var, ptr)
    LoadV(Var<C::N>, Ptr<C::N>),
    /// Load field element (var, ptr)
    LoadF(Felt<C::F>, Ptr<C::N>),
    /// Load extension field
    LoadE(Ext<C::F, C::EF>, Ptr<C::N>),
    /// Store variable at address
    StoreV(Ptr<C::N>, Var<C::N>),
    /// Store field element at adress
    StoreF(Ptr<C::N>, Felt<C::F>),
    /// Store extension field at adress
    StoreE(Ptr<C::N>, Ext<C::F, C::EF>),

    // Miscellaneous instructions.
    Num2BitsV(Array<C, Var<C::N>>, Usize<C::N>),
    Num2BitsF(Array<C, Var<C::N>>, Felt<C::F>),
    Poseidon2Permute(Array<C, Felt<C::F>>, Array<C, Felt<C::F>>),
    Poseidon2Compress(
        Array<C, Felt<C::F>>,
        Array<C, Felt<C::F>>,
        Array<C, Felt<C::F>>,
    ),
    TwoAdicGenerator(Felt<C::F>, Usize<C::N>),
    ReverseBitsLen(Usize<C::N>, Usize<C::N>, Usize<C::N>),
    ExpUsize(Felt<C::F>, Felt<C::F>, Usize<C::N>),
}
