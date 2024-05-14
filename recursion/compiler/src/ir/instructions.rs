use super::{Array, FriFoldInput, MemIndex, Ptr, TracedVec};
use super::{Config, Ext, Felt, Usize, Var};

/// An intermeddiate instruction set for implementing programs.
///
/// Programs written in the DSL can compile both to the recursive zkVM and the R1CS or Plonk-ish
/// circuits.
#[derive(Debug, Clone)]
pub enum DslIr<C: Config> {
    // Immediates.
    /// Assign immediate (2nd field) to a variable (1st field).
    ImmV(Var<C::N>, C::N),
    /// Assign field immediate (2nd field) to a field variable (1st field).
    ImmF(Felt<C::F>, C::F),
    /// Assign extension field immediate (2nd field) to an extension field variable (1st field).
    ImmE(Ext<C::F, C::EF>, C::EF),

    // Additions.
    /// Add two variables (2nd and 3rd field) and assigns result to a variable (1st field).
    AddV(Var<C::N>, Var<C::N>, Var<C::N>),
    /// Add a variable (2nd field) and an immediate (3rd field) and assigns result to a variable (1st field).
    AddVI(Var<C::N>, Var<C::N>, C::N),
    /// Add two field variables (2nd and 3rd field) and assigns result to a field variable (1st field).
    AddF(Felt<C::F>, Felt<C::F>, Felt<C::F>),
    /// Add a field variable (2nd field) and a field immediate (3rd field) and assigns result to a
    /// field variable (1st field).
    AddFI(Felt<C::F>, Felt<C::F>, C::F),
    /// Add two extension field variables (2nd and 3rd field) and assigns result to a field extension
    /// variable (1st field).
    AddE(Ext<C::F, C::EF>, Ext<C::F, C::EF>, Ext<C::F, C::EF>),
    /// Add an extension field variable (2nd field) and an extension field immediate (3rd field) and
    /// assigns result to an extension field variable (1st field).
    AddEI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::EF),
    /// Add an extension field variable (2nd field) and a field variable (3rd field) and assigns result
    /// to an extension field element (1st field).
    AddEF(Ext<C::F, C::EF>, Ext<C::F, C::EF>, Felt<C::F>),
    /// Add an extension field variable (2nd field) and a field immediate (3rd field) and assigns
    /// result to an extension field variable (1st field).
    AddEFI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::F),
    /// Add an field variable (2nd field) and an extension field immediate (3rd field) and assigns
    /// result to an extension field variable (1st field).
    AddEFFI(Ext<C::F, C::EF>, Felt<C::F>, C::EF),

    // Subtractions.
    /// Subtracts two variables (2nd and 3rd field) and assigns result to a variable (1st field).
    SubV(Var<C::N>, Var<C::N>, Var<C::N>),
    /// Subtracts a variables (2nd field) and an immediate (3rd field) and assigns result to a variable (1st field).
    SubVI(Var<C::N>, Var<C::N>, C::N),
    /// Subtracts an immediate (2nd field) and a variable (2nd field) and assigns result to a variable (1st field).
    SubVIN(Var<C::N>, C::N, Var<C::N>),
    /// Subtracts two field variables (2nd and 3rd field) and assigns result to a field variable (1st field).
    SubF(Felt<C::F>, Felt<C::F>, Felt<C::F>),
    /// Subtracts a field variable (2nd field) and a field immediate and assigns result to a field variable (1st field).
    SubFI(Felt<C::F>, Felt<C::F>, C::F),
    /// Subtracts a field immendate (2nd field) and a field variable (3rd field) and assigns result
    /// to a field variable (1st field).
    SubFIN(Felt<C::F>, C::F, Felt<C::F>),
    /// Subtracts two extension field variables (2nd and 3rd field) and assigns result to a extension
    /// field variable (1st field).
    SubE(Ext<C::F, C::EF>, Ext<C::F, C::EF>, Ext<C::F, C::EF>),
    /// Subtracts an extension field variable (2nd field) and an extension field immediate (2nd field) and assigns result
    /// to an extension field variable (1st field).
    SubEI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::EF),
    /// Subtracts an extension field immediate (2nd field) and an extension field variable (2nd field) and assigns result
    /// to an extension field variable (1st field).
    SubEIN(Ext<C::F, C::EF>, C::EF, Ext<C::F, C::EF>),
    /// Subtracts an extension field variable (2nd field) and a field immediate (2nd field) and assigns result to
    /// an extension field variable (1st field).
    SubEFI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::F),
    /// Subtracts an extension field variable (2nd field) and a field variable (2nd field) and assigns result to
    /// an extension field variable (1st field).
    SubEF(Ext<C::F, C::EF>, Ext<C::F, C::EF>, Felt<C::F>),

    // Multiplications.
    MulV(Var<C::N>, Var<C::N>, Var<C::N>),
    MulVI(Var<C::N>, Var<C::N>, C::N),
    MulF(Felt<C::F>, Felt<C::F>, Felt<C::F>),
    MulFI(Felt<C::F>, Felt<C::F>, C::F),
    MulE(Ext<C::F, C::EF>, Ext<C::F, C::EF>, Ext<C::F, C::EF>),
    MulEI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::EF),
    MulEFI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::F),
    MulEF(Ext<C::F, C::EF>, Ext<C::F, C::EF>, Felt<C::F>),

    // Divisions.
    DivF(Felt<C::F>, Felt<C::F>, Felt<C::F>),
    DivFI(Felt<C::F>, Felt<C::F>, C::F),
    DivFIN(Felt<C::F>, C::F, Felt<C::F>),
    DivE(Ext<C::F, C::EF>, Ext<C::F, C::EF>, Ext<C::F, C::EF>),
    DivEI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::EF),
    DivEIN(Ext<C::F, C::EF>, C::EF, Ext<C::F, C::EF>),
    DivEFI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::F),
    DivEFIN(Ext<C::F, C::EF>, C::F, Ext<C::F, C::EF>),
    DivEF(Ext<C::F, C::EF>, Ext<C::F, C::EF>, Felt<C::F>),

    // Negations.
    NegV(Var<C::N>, Var<C::N>),
    NegF(Felt<C::F>, Felt<C::F>),
    NegE(Ext<C::F, C::EF>, Ext<C::F, C::EF>),
    InvV(Var<C::N>, Var<C::N>),
    InvF(Felt<C::F>, Felt<C::F>),
    InvE(Ext<C::F, C::EF>, Ext<C::F, C::EF>),

    // Control flow.
    For(
        Usize<C::N>,
        Usize<C::N>,
        C::N,
        Var<C::N>,
        TracedVec<DslIr<C>>,
    ),
    IfEq(
        Var<C::N>,
        Var<C::N>,
        TracedVec<DslIr<C>>,
        TracedVec<DslIr<C>>,
    ),
    IfNe(
        Var<C::N>,
        Var<C::N>,
        TracedVec<DslIr<C>>,
        TracedVec<DslIr<C>>,
    ),
    IfEqI(Var<C::N>, C::N, TracedVec<DslIr<C>>, TracedVec<DslIr<C>>),
    IfNeI(Var<C::N>, C::N, TracedVec<DslIr<C>>, TracedVec<DslIr<C>>),
    Break,

    // Assertions.
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
    /// Allocate (ptr, len, size) a memory slice of length len
    Alloc(Ptr<C::N>, Usize<C::N>, usize),
    /// Load variable (var, ptr, index)
    LoadV(Var<C::N>, Ptr<C::N>, MemIndex<C::N>),
    /// Load field element (var, ptr, index)
    LoadF(Felt<C::F>, Ptr<C::N>, MemIndex<C::N>),
    /// Load extension field
    LoadE(Ext<C::F, C::EF>, Ptr<C::N>, MemIndex<C::N>),
    /// Store variable at address
    StoreV(Var<C::N>, Ptr<C::N>, MemIndex<C::N>),
    /// Store field element at adress
    StoreF(Felt<C::F>, Ptr<C::N>, MemIndex<C::N>),
    /// Store extension field at adress
    StoreE(Ext<C::F, C::EF>, Ptr<C::N>, MemIndex<C::N>),

    // Bits.
    Num2BitsV(Array<C, Var<C::N>>, Usize<C::N>),
    Num2BitsF(Array<C, Var<C::N>>, Felt<C::F>),
    CircuitNum2BitsV(Var<C::N>, usize, Vec<Var<C::N>>),
    CircuitNum2BitsF(Felt<C::F>, Vec<Var<C::N>>),
    ReverseBitsLen(Usize<C::N>, Usize<C::N>, Usize<C::N>),

    // Hashing.
    Poseidon2PermuteBabyBear(Array<C, Felt<C::F>>, Array<C, Felt<C::F>>),
    Poseidon2CompressBabyBear(
        Array<C, Felt<C::F>>,
        Array<C, Felt<C::F>>,
        Array<C, Felt<C::F>>,
    ),
    CircuitPoseidon2Permute([Var<C::N>; 3]),

    // Miscellaneous instructions.
    HintBitsU(Array<C, Var<C::N>>, Usize<C::N>),
    HintBitsV(Array<C, Var<C::N>>, Var<C::N>),
    HintBitsF(Array<C, Var<C::N>>, Felt<C::F>),
    PrintV(Var<C::N>),
    PrintF(Felt<C::F>),
    PrintE(Ext<C::F, C::EF>),
    Error(),
    TwoAdicGenerator(Felt<C::F>, Usize<C::N>),
    ExpUsizeV(Var<C::N>, Var<C::N>, Usize<C::N>),
    ExpUsizeF(Felt<C::F>, Felt<C::F>, Usize<C::N>),
    Ext2Felt(Array<C, Felt<C::F>>, Ext<C::F, C::EF>),
    HintLen(Var<C::N>),
    HintVars(Array<C, Var<C::N>>),
    HintFelts(Array<C, Felt<C::F>>),
    HintExts(Array<C, Ext<C::F, C::EF>>),
    WitnessVar(Var<C::N>, u32),
    WitnessFelt(Felt<C::F>, u32),
    WitnessExt(Ext<C::F, C::EF>, u32),
    Commit(Felt<C::F>, Var<C::N>),
    Halt,

    // Public inputs for circuits.
    CircuitCommitVkeyHash(Var<C::N>),
    CircuitCommitCommitedValuesDigest(Var<C::N>),

    // FRI specific instructions.
    FriFold(Var<C::N>, Array<C, FriFoldInput<C>>),
    CircuitSelectV(Var<C::N>, Var<C::N>, Var<C::N>, Var<C::N>),
    CircuitSelectF(Var<C::N>, Felt<C::F>, Felt<C::F>, Felt<C::F>),
    CircuitSelectE(
        Var<C::N>,
        Ext<C::F, C::EF>,
        Ext<C::F, C::EF>,
        Ext<C::F, C::EF>,
    ),
    CircuitExt2Felt([Felt<C::F>; 4], Ext<C::F, C::EF>),
    CircuitFelts2Ext([Felt<C::F>; 4], Ext<C::F, C::EF>),

    // Debugging instructions.
    LessThan(Var<C::N>, Var<C::N>, Var<C::N>),
    CycleTracker(String),
}
