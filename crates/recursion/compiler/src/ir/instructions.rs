use std::{
    borrow::Cow,
    ops::{Deref, Range},
};

use backtrace::Backtrace;
use sp1_hypercube::septic_curve::SepticCurve;
use sp1_primitives::{SP1ExtensionField, SP1Field};
use sp1_recursion_executor::RecursionPublicValues;

use super::{Config, Ext, Felt, Var};

/// An intermeddiate instruction set for implementing programs.
///
/// Programs written in the DSL can compile both to the recursive zkVM and the R1CS or Plonk-ish
/// circuits.
#[derive(Debug, Clone)]
pub enum DslIr<C: Config> {
    // Immediates.
    /// Assigns an immediate to a variable (var = imm).
    ImmV(Var<C::N>, C::N),
    /// Assigns a field immediate to a field element (felt = field imm).
    ImmF(Felt<SP1Field>, SP1Field),
    /// Assigns an ext field immediate to an extension field element (ext = ext field imm).
    ImmE(Ext<SP1Field, SP1ExtensionField>, SP1ExtensionField),

    // Additions.
    /// Add two variables (var = var + var).
    AddV(Var<C::N>, Var<C::N>, Var<C::N>),
    /// Add a variable and an immediate (var = var + imm).
    AddVI(Var<C::N>, Var<C::N>, C::N),
    /// Add two field elements (felt = felt + felt).
    AddF(Felt<SP1Field>, Felt<SP1Field>, Felt<SP1Field>),
    /// Add a field element and a field immediate (felt = felt + field imm).
    AddFI(Felt<SP1Field>, Felt<SP1Field>, SP1Field),
    /// Add two extension field elements (ext = ext + ext).
    AddE(
        Ext<SP1Field, SP1ExtensionField>,
        Ext<SP1Field, SP1ExtensionField>,
        Ext<SP1Field, SP1ExtensionField>,
    ),
    /// Add an extension field element and an ext field immediate (ext = ext + ext field imm).
    AddEI(Ext<SP1Field, SP1ExtensionField>, Ext<SP1Field, SP1ExtensionField>, SP1ExtensionField),
    /// Add an extension field element and a field element (ext = ext + felt).
    AddEF(Ext<SP1Field, SP1ExtensionField>, Ext<SP1Field, SP1ExtensionField>, Felt<SP1Field>),
    /// Add a field element and an ext field immediate (ext = felt + ext field imm).
    AddEFFI(Ext<SP1Field, SP1ExtensionField>, Felt<SP1Field>, SP1ExtensionField),

    // Subtractions.
    /// Subtracts two variables (var = var - var).
    SubV(Var<C::N>, Var<C::N>, Var<C::N>),
    /// Subtracts a variable and an immediate (var = var - imm).
    SubVI(Var<C::N>, Var<C::N>, C::N),
    /// Subtracts an immediate and a variable (var = imm - var).
    SubVIN(Var<C::N>, C::N, Var<C::N>),
    /// Subtracts two field elements (felt = felt - felt).
    SubF(Felt<SP1Field>, Felt<SP1Field>, Felt<SP1Field>),
    /// Subtracts a field element and a field immediate (felt = felt - field imm).
    SubFI(Felt<SP1Field>, Felt<SP1Field>, SP1Field),
    /// Subtracts a field immediate and a field element (felt = field imm - felt).
    SubFIN(Felt<SP1Field>, SP1Field, Felt<SP1Field>),
    /// Subtracts two extension field elements (ext = ext - ext).
    SubE(
        Ext<SP1Field, SP1ExtensionField>,
        Ext<SP1Field, SP1ExtensionField>,
        Ext<SP1Field, SP1ExtensionField>,
    ),
    /// Subtrancts an extension field element and an extension field immediate (ext = ext - ext
    /// field imm).
    SubEI(Ext<SP1Field, SP1ExtensionField>, Ext<SP1Field, SP1ExtensionField>, SP1ExtensionField),
    /// Subtracts an extension field immediate and an extension field element (ext = ext field imm
    /// - ext).
    SubEIN(Ext<SP1Field, SP1ExtensionField>, SP1ExtensionField, Ext<SP1Field, SP1ExtensionField>),
    /// Subtracts an extension field element and a field element (ext = ext - felt).
    SubEF(Ext<SP1Field, SP1ExtensionField>, Ext<SP1Field, SP1ExtensionField>, Felt<SP1Field>),

    // Multiplications.
    /// Multiplies two variables (var = var * var).
    MulV(Var<C::N>, Var<C::N>, Var<C::N>),
    /// Multiplies a variable and an immediate (var = var * imm).
    MulVI(Var<C::N>, Var<C::N>, C::N),
    /// Multiplies two field elements (felt = felt * felt).
    MulF(Felt<SP1Field>, Felt<SP1Field>, Felt<SP1Field>),
    /// Multiplies a field element and a field immediate (felt = felt * field imm).
    MulFI(Felt<SP1Field>, Felt<SP1Field>, SP1Field),
    /// Multiplies two extension field elements (ext = ext * ext).
    MulE(
        Ext<SP1Field, SP1ExtensionField>,
        Ext<SP1Field, SP1ExtensionField>,
        Ext<SP1Field, SP1ExtensionField>,
    ),
    /// Multiplies an extension field element and an extension field immediate (ext = ext * ext
    /// field imm).
    MulEI(Ext<SP1Field, SP1ExtensionField>, Ext<SP1Field, SP1ExtensionField>, SP1ExtensionField),
    /// Multiplies an extension field element and a field element (ext = ext * felt).
    MulEF(Ext<SP1Field, SP1ExtensionField>, Ext<SP1Field, SP1ExtensionField>, Felt<SP1Field>),

    // Divisions.
    /// Divides two variables (var = var / var).
    DivF(Felt<SP1Field>, Felt<SP1Field>, Felt<SP1Field>),
    /// Divides a field element and a field immediate (felt = felt / field imm).
    DivFI(Felt<SP1Field>, Felt<SP1Field>, SP1Field),
    /// Divides a field immediate and a field element (felt = field imm / felt).
    DivFIN(Felt<SP1Field>, SP1Field, Felt<SP1Field>),
    /// Divides two extension field elements (ext = ext / ext).
    DivE(
        Ext<SP1Field, SP1ExtensionField>,
        Ext<SP1Field, SP1ExtensionField>,
        Ext<SP1Field, SP1ExtensionField>,
    ),
    /// Divides an extension field element and an extension field immediate (ext = ext / ext field
    /// imm).
    DivEI(Ext<SP1Field, SP1ExtensionField>, Ext<SP1Field, SP1ExtensionField>, SP1ExtensionField),
    /// Divides and extension field immediate and an extension field element (ext = ext field imm /
    /// ext).
    DivEIN(Ext<SP1Field, SP1ExtensionField>, SP1ExtensionField, Ext<SP1Field, SP1ExtensionField>),
    /// Divides an extension field element and a field element (ext = ext / felt).
    DivEF(Ext<SP1Field, SP1ExtensionField>, Ext<SP1Field, SP1ExtensionField>, Felt<SP1Field>),

    // Negations.
    /// Negates a variable (var = -var).
    NegV(Var<C::N>, Var<C::N>),
    /// Negates a field element (felt = -felt).
    NegF(Felt<SP1Field>, Felt<SP1Field>),
    /// Negates an extension field element (ext = -ext).
    NegE(Ext<SP1Field, SP1ExtensionField>, Ext<SP1Field, SP1ExtensionField>),
    /// Inverts a variable (var = 1 / var).
    InvV(Var<C::N>, Var<C::N>),
    /// Inverts a field element (felt = 1 / felt).
    InvF(Felt<SP1Field>, Felt<SP1Field>),
    /// Inverts an extension field element (ext = 1 / ext).
    InvE(Ext<SP1Field, SP1ExtensionField>, Ext<SP1Field, SP1ExtensionField>),

    /// Selects order of felts based on a bit (should_swap, first result, second result, first
    /// input, second input)
    Select(Felt<SP1Field>, Felt<SP1Field>, Felt<SP1Field>, Felt<SP1Field>, Felt<SP1Field>),

    // Assertions.
    /// Assert that two variables are equal (var == var).
    AssertEqV(Var<C::N>, Var<C::N>),
    /// Assert that two variables are not equal (var != var).
    AssertNeV(Var<C::N>, Var<C::N>),
    /// Assert that two field elements are equal (felt == felt).
    AssertEqF(Felt<SP1Field>, Felt<SP1Field>),
    /// Assert that two field elements are not equal (felt != felt).
    AssertNeF(Felt<SP1Field>, Felt<SP1Field>),
    /// Assert that two extension field elements are equal (ext == ext).
    AssertEqE(Ext<SP1Field, SP1ExtensionField>, Ext<SP1Field, SP1ExtensionField>),
    /// Assert that two extension field elements are not equal (ext != ext).
    AssertNeE(Ext<SP1Field, SP1ExtensionField>, Ext<SP1Field, SP1ExtensionField>),
    /// Assert that a variable is equal to an immediate (var == imm).
    AssertEqVI(Var<C::N>, C::N),
    /// Assert that a variable is not equal to an immediate (var != imm).
    AssertNeVI(Var<C::N>, C::N),
    /// Assert that a field element is equal to a field immediate (felt == field imm).
    AssertEqFI(Felt<SP1Field>, SP1Field),
    /// Assert that a field element is not equal to a field immediate (felt != field imm).
    AssertNeFI(Felt<SP1Field>, SP1Field),
    /// Assert that an extension field element is equal to an extension field immediate (ext == ext
    /// field imm).
    AssertEqEI(Ext<SP1Field, SP1ExtensionField>, SP1ExtensionField),
    /// Assert that an extension field element is not equal to an extension field immediate (ext !=
    /// ext field imm).
    AssertNeEI(Ext<SP1Field, SP1ExtensionField>, SP1ExtensionField),

    /// Force reduction of field elements in circuit.
    ReduceE(Ext<SP1Field, SP1ExtensionField>),

    // Bits.
    /// Decompose a variable into size bits (bits = num2bits(var, size)). Should only be used when
    /// target is a gnark circuit.
    CircuitNum2BitsV(Var<C::N>, usize, Vec<Var<C::N>>),
    /// Decompose a field element into bits (bits = num2bits(felt)). Should only be used when
    /// target is a gnark circuit.
    CircuitNum2BitsF(Felt<SP1Field>, Vec<Var<C::N>>),
    /// Convert a Felt to a Var in a circuit. Avoids decomposing to bits and then reconstructing.
    CircuitFelt2Var(Felt<SP1Field>, Var<C::N>),

    // Hashing.
    /// Performs the external linear layer of Poseidon2.
    Poseidon2ExternalLinearLayer(
        Box<([Ext<SP1Field, SP1ExtensionField>; 4], [Ext<SP1Field, SP1ExtensionField>; 4])>,
    ),
    /// Performs the internal linear layer of Poseidon2.
    Poseidon2InternalLinearLayer(
        Box<([Ext<SP1Field, SP1ExtensionField>; 4], [Ext<SP1Field, SP1ExtensionField>; 4])>,
    ),
    /// Performs the external SBOX mapping for Poseidon2 in a batch.
    Poseidon2ExternalSBOX(Ext<SP1Field, SP1ExtensionField>, Ext<SP1Field, SP1ExtensionField>),
    /// Performs the internal SBOX mapping for Poseidon2 in a batch.
    Poseidon2InternalSBOX(Ext<SP1Field, SP1ExtensionField>, Ext<SP1Field, SP1ExtensionField>),

    /// Permutes an array of Bn254 elements using Poseidon2 (output = p2_permute(array)). Should
    /// only be used when target is a gnark circuit.
    CircuitPoseidon2Permute([Var<C::N>; 3]),
    /// Permutates an array of SP1Field elements in the circuit.
    CircuitPoseidon2PermuteKoalaBear(Box<[Felt<SP1Field>; 16]>),
    /// Permutates an array of SP1Field elements in the circuit using the skinny precompile.
    CircuitV2Poseidon2PermuteKoalaBear(Box<([Felt<SP1Field>; 16], [Felt<SP1Field>; 16])>),
    /// Commits the public values.
    CircuitV2CommitPublicValues(Box<RecursionPublicValues<Felt<SP1Field>>>),

    /// Decompose hint operation of a field element into an array. (output = num2bits(felt)).
    CircuitV2HintBitsF(Vec<Felt<SP1Field>>, Felt<SP1Field>),
    /// Prints a variable.
    PrintV(Var<C::N>),
    /// Prints a field element.
    PrintF(Felt<SP1Field>),
    /// Prints an extension field element.
    PrintE(Ext<SP1Field, SP1ExtensionField>),
    /// Throws an error.
    Error(),

    /// Hint an array of field elements.
    CircuitV2HintFelts(Felt<SP1Field>, usize),
    /// Hint an array of extension field elements.
    CircuitV2HintExts(Ext<SP1Field, SP1ExtensionField>, usize),
    /// Witness a variable. Should only be used when target is a gnark circuit.
    WitnessVar(Var<C::N>, u32),
    /// Witness a field element. Should only be used when target is a gnark circuit.
    WitnessFelt(Felt<SP1Field>, u32),
    /// Witness an extension field element. Should only be used when target is a gnark circuit.
    WitnessExt(Ext<SP1Field, SP1ExtensionField>, u32),
    /// Label a field element as the ith public input.
    Commit(Felt<SP1Field>, Var<C::N>),

    // Public inputs for circuits.
    /// Asserts that the inputted var is equal the circuit's vkey hash public input. Should only be
    /// used when target is a gnark circuit.
    CircuitCommitVkeyHash(Var<C::N>),
    /// Asserts that the inputted var is equal the circuit's committed values digest public input.
    /// Should only be used when target is a gnark circuit.
    CircuitCommitCommittedValuesDigest(Var<C::N>),
    /// Asserts that the inputted var is equal the circuit's exit code public input. Should only be
    /// used when target is a gnark circuit.
    CircuitCommitExitCode(Var<C::N>),
    /// Asserts that the inputted var is equal the circuit's vk root public input. Should only be
    /// used when target is a gnark circuit.
    CircuitCommitVkRoot(Var<C::N>),
    /// Asserts that the inputted var is equal the circuit's proof nonce public input. Should only
    /// be used when target is a gnark circuit.
    CircuitCommitProofNonce(Var<C::N>),
    /// Adds two elliptic curve points. (sum, point_1, point_2).
    CircuitV2HintAddCurve(
        Box<(
            SepticCurve<Felt<SP1Field>>,
            SepticCurve<Felt<SP1Field>>,
            SepticCurve<Felt<SP1Field>>,
        )>,
    ),

    /// Select's a variable based on a condition. (select(cond, true_val, false_val) => output).
    /// Should only be used when target is a gnark circuit.
    CircuitSelectV(Var<C::N>, Var<C::N>, Var<C::N>, Var<C::N>),
    /// Select's a field element based on a condition. (select(cond, true_val, false_val) =>
    /// output). Should only be used when target is a gnark circuit.
    CircuitSelectF(Var<C::N>, Felt<SP1Field>, Felt<SP1Field>, Felt<SP1Field>),
    /// Select's an extension field element based on a condition. (select(cond, true_val,
    /// false_val) => output). Should only be used when target is a gnark circuit.
    CircuitSelectE(
        Var<C::N>,
        Ext<SP1Field, SP1ExtensionField>,
        Ext<SP1Field, SP1ExtensionField>,
        Ext<SP1Field, SP1ExtensionField>,
    ),
    /// Converts an ext to a slice of felts. Should only be used when target is a gnark circuit.
    CircuitExt2Felt([Felt<SP1Field>; 4], Ext<SP1Field, SP1ExtensionField>),
    /// Converts a slice of felts to an ext. Should only be used when target is a gnark circuit.
    CircuitFelts2Ext([Felt<SP1Field>; 4], Ext<SP1Field, SP1ExtensionField>),
    /// Evaluates a single `eq` computation, while verifying that the first element is a bit.
    /// Should only be used when target is a gnark circuit.
    EqEval(Felt<SP1Field>, Ext<SP1Field, SP1ExtensionField>, Ext<SP1Field, SP1ExtensionField>),
    /// Converts a slice of felts to an ext, using a chip. Should be used for wrap.
    CircuitChipExt2Felt([Felt<SP1Field>; 4], Ext<SP1Field, SP1ExtensionField>),
    /// Converts an ext to a slice of felts, using a chip. Should be used for wrap.
    CircuitChipFelt2Ext(Ext<SP1Field, SP1ExtensionField>, [Felt<SP1Field>; 4]),

    // Debugging instructions.
    /// Tracks the number of cycles used by a block of code annotated by the string input.
    CycleTrackerV2Enter(Cow<'static, str>),
    /// Tracks the number of cycles used by a block of code annotated by the string input.
    CycleTrackerV2Exit,

    // Structuring IR constructors.
    /// Blocks that may be executed in parallel.
    Parallel(Vec<DslIrBlock<C>>),

    /// Pass a backtrace for debugging.
    DebugBacktrace(Backtrace),
}

/// A block of instructions.
#[derive(Clone, Default, Debug)]
pub struct DslIrBlock<C: Config> {
    pub ops: Vec<DslIr<C>>,
    pub addrs_written: Range<u32>,
}

#[derive(Clone, Debug)]
pub struct DslIrProgram<C: Config>(DslIrBlock<C>);

impl<C: Config> DslIrProgram<C> {
    /// # Safety
    /// The given block must represent a well formed program. This is defined as the following:
    /// - reads are performed after writes, according to a "happens-before" relation; and
    /// - an address is written to at most once.
    ///
    /// The "happens-before" relation is defined as follows:
    /// - It is a strict partial order, meaning it is transitive, irreflexive, and asymmetric.
    /// - Contiguous sequences of instructions that are not [`DslIr::Parallel`] in a [`DslIrBlock`]
    ///   are linearly ordered. Call these sequences "sequential blocks."
    /// - For each `DslIrBlock` in the `DslIr::Parallel` variant:
    ///   - The block's first instruction comes after the last instruction in the parent's previous
    ///     sequential block. if it exists.
    ///   - The block's last instruction comes before the first instruction in the parent's next
    ///     sequential block, if it exists.
    ///   - If the sequential blocks mentioned in eiither of the previous two rules do not exist,
    ///     then the situation is that of two consecutive [`DslIr::Parallel`] instructions `x` and
    ///     `y`. Then each last instruction of `x` comes before each first instruction of `y`.
    pub unsafe fn new_unchecked(block: DslIrBlock<C>) -> Self {
        Self(block)
    }

    pub fn into_inner(self) -> DslIrBlock<C> {
        self.0
    }
}

impl<C: Config> Default for DslIrProgram<C> {
    fn default() -> Self {
        // SAFETY: An empty block is always well formed.
        unsafe { Self::new_unchecked(DslIrBlock::default()) }
    }
}

impl<C: Config> Deref for DslIrProgram<C> {
    type Target = DslIrBlock<C>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
