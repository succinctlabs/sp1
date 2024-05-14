use super::{Array, FriFoldInput, MemIndex, Ptr, TracedVec};
use super::{Config, Ext, Felt, Usize, Var};

/// An intermeddiate instruction set for implementing programs.
///
/// Programs written in the DSL can compile both to the recursive zkVM and the R1CS or Plonk-ish
/// circuits.
#[derive(Debug, Clone)]
pub enum DslIr<C: Config> {
    // Immediates.
    /// Assign immediate to a variable (var = imm).
    ImmV(Var<C::N>, C::N),
    /// Assign field immediate to a field element (felt = field imm).
    ImmF(Felt<C::F>, C::F),
    /// Assign ext field immediate to an extension field element (ext = ext field imm).
    ImmE(Ext<C::F, C::EF>, C::EF),

    // Additions.
    /// Add two variables (var = var + var).
    AddV(Var<C::N>, Var<C::N>, Var<C::N>),
    /// Add a variable and an immediate (var = var + imm).
    AddVI(Var<C::N>, Var<C::N>, C::N),
    /// Add two field elements (felt = felt + felt).
    AddF(Felt<C::F>, Felt<C::F>, Felt<C::F>),
    /// Add a field element and a field immediate (felt = felt + field imm).
    AddFI(Felt<C::F>, Felt<C::F>, C::F),
    /// Add two extension field elements (ext = ext + ext).
    AddE(Ext<C::F, C::EF>, Ext<C::F, C::EF>, Ext<C::F, C::EF>),
    /// Add an extension field element and an ext field immediate (ext = ext + ext field imm).
    AddEI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::EF),
    /// Add an extension field element and a field element (ext = ext + felt).
    AddEF(Ext<C::F, C::EF>, Ext<C::F, C::EF>, Felt<C::F>),
    /// Add an extension field element and a field immediate (ext = ext + field imm).
    AddEFI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::F),
    /// Add a field element and an ext field immediate (ext = felt + ext field imm).
    AddEFFI(Ext<C::F, C::EF>, Felt<C::F>, C::EF),

    // Subtractions.
    /// Subtracts two variables (var = var - var).
    SubV(Var<C::N>, Var<C::N>, Var<C::N>),
    /// Subtracts a variable and an immediate (var = var - imm).
    SubVI(Var<C::N>, Var<C::N>, C::N),
    /// Subtracts an immediate and a variable (var = imm - var).    
    SubVIN(Var<C::N>, C::N, Var<C::N>),
    /// Subtracts two field elements (felt = felt - felt).
    SubF(Felt<C::F>, Felt<C::F>, Felt<C::F>),
    /// Subtracts a field element and a field immediate (felt = felt - field imm).
    SubFI(Felt<C::F>, Felt<C::F>, C::F),
    /// Subtracts a field immediate and a field element (felt = field imm - felt).
    SubFIN(Felt<C::F>, C::F, Felt<C::F>),
    /// Subtracts two extension field elements (ext = ext - ext).
    SubE(Ext<C::F, C::EF>, Ext<C::F, C::EF>, Ext<C::F, C::EF>),
    /// Subtrancts an extension field element and an extension field immediate (ext = ext - ext field imm).
    SubEI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::EF),
    /// Subtracts an extension field immediate and an extension field element (ext = ext field imm - ext).
    SubEIN(Ext<C::F, C::EF>, C::EF, Ext<C::F, C::EF>),
    /// Subtracts an extension field element and a field immediate (ext = ext - field imm).
    SubEFI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::F),
    /// Subtracts an extension field element and a field element (ext = ext - felt).
    SubEF(Ext<C::F, C::EF>, Ext<C::F, C::EF>, Felt<C::F>),

    // Multiplications.
    /// Multiplies two variables (var = var * var).
    MulV(Var<C::N>, Var<C::N>, Var<C::N>),
    /// Multiplies a variable and an immediate (var = var * imm).
    MulVI(Var<C::N>, Var<C::N>, C::N),
    /// Multiplies two field elements (felt = felt * felt).
    MulF(Felt<C::F>, Felt<C::F>, Felt<C::F>),
    /// Multiplies a field element and a field immediate (felt = felt * field imm).
    MulFI(Felt<C::F>, Felt<C::F>, C::F),
    /// Multiplies two extension field elements (ext = ext * ext).
    MulE(Ext<C::F, C::EF>, Ext<C::F, C::EF>, Ext<C::F, C::EF>),
    /// Multiplies an extension field element and an extension field immediate (ext = ext * ext field imm).
    MulEI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::EF),
    /// Multiplies an extension field element and a field immediate (ext = ext * field imm).
    MulEFI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::F),
    /// Multiplies an extension field element and a field element (ext = ext * felt).
    MulEF(Ext<C::F, C::EF>, Ext<C::F, C::EF>, Felt<C::F>),

    // Divisions.
    /// Divides two variables (var = var / var).
    DivF(Felt<C::F>, Felt<C::F>, Felt<C::F>),
    /// Divides a field element and a field immediate (felt = felt / field imm).
    DivFI(Felt<C::F>, Felt<C::F>, C::F),
    /// Divides a field immediate and a field element (felt = field imm / felt).
    DivFIN(Felt<C::F>, C::F, Felt<C::F>),
    /// Divides two extension field elements (ext = ext / ext).
    DivE(Ext<C::F, C::EF>, Ext<C::F, C::EF>, Ext<C::F, C::EF>),
    /// Divides an extension field element and an extension field immediate (ext = ext / ext field imm).
    DivEI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::EF),
    /// Divides and extension field immediate and an extension field element (ext = ext field imm / ext).
    DivEIN(Ext<C::F, C::EF>, C::EF, Ext<C::F, C::EF>),
    /// Divides an extension field element and a field immediate (ext = ext / field imm).
    DivEFI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::F),
    /// Divides a field immediate and an extension field element (ext = field imm / ext).
    DivEFIN(Ext<C::F, C::EF>, C::F, Ext<C::F, C::EF>),
    /// Divides an extension field element and a field element (ext = ext / felt).
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
    /// Store field element at address
    StoreF(Felt<C::F>, Ptr<C::N>, MemIndex<C::N>),
    /// Store extension field at address
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
