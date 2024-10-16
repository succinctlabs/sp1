use sp1_recursion_core::air::RecursionPublicValues;

use super::{
    Array, CircuitV2FriFoldInput, CircuitV2FriFoldOutput, Config, Ext, Felt, FriFoldInput,
    MemIndex, Ptr, TracedVec, Usize, Var,
};

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
    ImmF(Felt<C::F>, C::F),
    /// Assigns an ext field immediate to an extension field element (ext = ext field imm).
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
    /// Subtrancts an extension field element and an extension field immediate (ext = ext - ext
    /// field imm).
    SubEI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::EF),
    /// Subtracts an extension field immediate and an extension field element (ext = ext field imm
    /// - ext).
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
    /// Multiplies an extension field element and an extension field immediate (ext = ext * ext
    /// field imm).
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
    /// Divides an extension field element and an extension field immediate (ext = ext / ext field
    /// imm).
    DivEI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::EF),
    /// Divides and extension field immediate and an extension field element (ext = ext field imm /
    /// ext).
    DivEIN(Ext<C::F, C::EF>, C::EF, Ext<C::F, C::EF>),
    /// Divides an extension field element and a field immediate (ext = ext / field imm).
    DivEFI(Ext<C::F, C::EF>, Ext<C::F, C::EF>, C::F),
    /// Divides a field immediate and an extension field element (ext = field imm / ext).
    DivEFIN(Ext<C::F, C::EF>, C::F, Ext<C::F, C::EF>),
    /// Divides an extension field element and a field element (ext = ext / felt).
    DivEF(Ext<C::F, C::EF>, Ext<C::F, C::EF>, Felt<C::F>),

    // Negations.
    /// Negates a variable (var = -var).
    NegV(Var<C::N>, Var<C::N>),
    /// Negates a field element (felt = -felt).
    NegF(Felt<C::F>, Felt<C::F>),
    /// Negates an extension field element (ext = -ext).
    NegE(Ext<C::F, C::EF>, Ext<C::F, C::EF>),
    /// Inverts a variable (var = 1 / var).
    InvV(Var<C::N>, Var<C::N>),
    /// Inverts a field element (felt = 1 / felt).
    InvF(Felt<C::F>, Felt<C::F>),
    /// Inverts an extension field element (ext = 1 / ext).
    InvE(Ext<C::F, C::EF>, Ext<C::F, C::EF>),

    // Control flow.
    /// Executes a for loop with the parameters (start step value, end step value, step size, step
    /// variable, body).
    For(Box<(Usize<C::N>, Usize<C::N>, C::N, Var<C::N>, TracedVec<DslIr<C>>)>),
    /// Executes an equal conditional branch with the parameters (lhs var, rhs var, then body, else
    /// body).
    IfEq(Box<(Var<C::N>, Var<C::N>, TracedVec<DslIr<C>>, TracedVec<DslIr<C>>)>),
    /// Executes a not equal conditional branch with the parameters (lhs var, rhs var, then body,
    /// else body).
    IfNe(Box<(Var<C::N>, Var<C::N>, TracedVec<DslIr<C>>, TracedVec<DslIr<C>>)>),
    /// Executes an equal conditional branch with the parameters (lhs var, rhs imm, then body, else
    /// body).
    IfEqI(Box<(Var<C::N>, C::N, TracedVec<DslIr<C>>, TracedVec<DslIr<C>>)>),
    /// Executes a not equal conditional branch with the parameters (lhs var, rhs imm, then body,
    /// else body).
    IfNeI(Box<(Var<C::N>, C::N, TracedVec<DslIr<C>>, TracedVec<DslIr<C>>)>),
    /// Break out of a for loop.
    Break,

    // Assertions.
    /// Assert that two variables are equal (var == var).
    AssertEqV(Var<C::N>, Var<C::N>),
    /// Assert that two variables are not equal (var != var).
    AssertNeV(Var<C::N>, Var<C::N>),
    /// Assert that two field elements are equal (felt == felt).
    AssertEqF(Felt<C::F>, Felt<C::F>),
    /// Assert that two field elements are not equal (felt != felt).
    AssertNeF(Felt<C::F>, Felt<C::F>),
    /// Assert that two extension field elements are equal (ext == ext).
    AssertEqE(Ext<C::F, C::EF>, Ext<C::F, C::EF>),
    /// Assert that two extension field elements are not equal (ext != ext).
    AssertNeE(Ext<C::F, C::EF>, Ext<C::F, C::EF>),
    /// Assert that a variable is equal to an immediate (var == imm).
    AssertEqVI(Var<C::N>, C::N),
    /// Assert that a variable is not equal to an immediate (var != imm).
    AssertNeVI(Var<C::N>, C::N),
    /// Assert that a field element is equal to a field immediate (felt == field imm).
    AssertEqFI(Felt<C::F>, C::F),
    /// Assert that a field element is not equal to a field immediate (felt != field imm).
    AssertNeFI(Felt<C::F>, C::F),
    /// Assert that an extension field element is equal to an extension field immediate (ext == ext
    /// field imm).
    AssertEqEI(Ext<C::F, C::EF>, C::EF),
    /// Assert that an extension field element is not equal to an extension field immediate (ext !=
    /// ext field imm).
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

    /// Force reduction of field elements in circuit.
    ReduceE(Ext<C::F, C::EF>),

    // Bits.
    /// Decompose a variable into size bits (bits = num2bits(var, size)). Should only be used when
    /// target is a gnark circuit.
    CircuitNum2BitsV(Var<C::N>, usize, Vec<Var<C::N>>),
    /// Decompose a field element into bits (bits = num2bits(felt)). Should only be used when
    /// target is a gnark circuit.
    CircuitNum2BitsF(Felt<C::F>, Vec<Var<C::N>>),
    /// Convert a Felt to a Var in a circuit. Avoids decomposing to bits and then reconstructing.
    CircuitFelt2Var(Felt<C::F>, Var<C::N>),

    // Hashing.
    /// Permutes an array of baby bear elements using Poseidon2 (output = p2_permute(array)).
    Poseidon2PermuteBabyBear(Box<(Array<C, Felt<C::F>>, Array<C, Felt<C::F>>)>),
    /// Compresses two baby bear element arrays using Poseidon2 (output = p2_compress(array1,
    /// array2)).
    Poseidon2CompressBabyBear(
        Box<(Array<C, Felt<C::F>>, Array<C, Felt<C::F>>, Array<C, Felt<C::F>>)>,
    ),
    /// Absorb an array of baby bear elements for a specified hash instance.
    Poseidon2AbsorbBabyBear(Var<C::N>, Array<C, Felt<C::F>>),
    /// Finalize and return the hash digest of a specified hash instance.
    Poseidon2FinalizeBabyBear(Var<C::N>, Array<C, Felt<C::F>>),
    /// Permutes an array of Bn254 elements using Poseidon2 (output = p2_permute(array)). Should
    /// only be used when target is a gnark circuit.
    CircuitPoseidon2Permute([Var<C::N>; 3]),
    /// Permutates an array of BabyBear elements in the circuit.
    CircuitPoseidon2PermuteBabyBear(Box<[Felt<C::F>; 16]>),
    /// Permutates an array of BabyBear elements in the circuit using the skinny precompile.
    CircuitV2Poseidon2PermuteBabyBear(Box<([Felt<C::F>; 16], [Felt<C::F>; 16])>),
    /// Commits the public values.
    CircuitV2CommitPublicValues(Box<RecursionPublicValues<Felt<C::F>>>),

    // Miscellaneous instructions.
    /// Decompose hint operation of a usize into an array. (output = num2bits(usize)).
    HintBitsU(Array<C, Var<C::N>>, Usize<C::N>),
    /// Decompose hint operation of a variable into an array. (output = num2bits(var)).
    HintBitsV(Array<C, Var<C::N>>, Var<C::N>),
    /// Decompose hint operation of a field element into an array. (output = num2bits(felt)).
    HintBitsF(Array<C, Var<C::N>>, Felt<C::F>),
    /// Decompose hint operation of a field element into an array. (output = num2bits(felt)).
    CircuitV2HintBitsF(Vec<Felt<C::F>>, Felt<C::F>),
    /// Prints a variable.
    PrintV(Var<C::N>),
    /// Prints a field element.
    PrintF(Felt<C::F>),
    /// Prints an extension field element.
    PrintE(Ext<C::F, C::EF>),
    /// Throws an error.
    Error(),

    /// Converts an ext to a slice of felts.  
    HintExt2Felt(Array<C, Felt<C::F>>, Ext<C::F, C::EF>),
    /// Hint the length of the next array.  
    HintLen(Var<C::N>),
    /// Hint an array of variables.
    HintVars(Array<C, Var<C::N>>),
    /// Hint an array of field elements.
    HintFelts(Array<C, Felt<C::F>>),
    /// Hint an array of extension field elements.
    HintExts(Array<C, Ext<C::F, C::EF>>),
    /// Hint an array of field elements.
    CircuitV2HintFelts(Vec<Felt<C::F>>),
    /// Hint an array of extension field elements.
    CircuitV2HintExts(Vec<Ext<C::F, C::EF>>),
    /// Witness a variable. Should only be used when target is a gnark circuit.
    WitnessVar(Var<C::N>, u32),
    /// Witness a field element. Should only be used when target is a gnark circuit.
    WitnessFelt(Felt<C::F>, u32),
    /// Witness an extension field element. Should only be used when target is a gnark circuit.
    WitnessExt(Ext<C::F, C::EF>, u32),
    /// Label a field element as the ith public input.
    Commit(Felt<C::F>, Var<C::N>),
    /// Registers a field element to the public inputs.
    RegisterPublicValue(Felt<C::F>),
    /// Operation to halt the program. Should be the last instruction in the program.  
    Halt,

    // Public inputs for circuits.
    /// Asserts that the inputted var is equal the circuit's vkey hash public input. Should only be
    /// used when target is a gnark circuit.
    CircuitCommitVkeyHash(Var<C::N>),
    /// Asserts that the inputted var is equal the circuit's committed values digest public input.
    /// Should only be used when target is a gnark circuit.
    CircuitCommitCommittedValuesDigest(Var<C::N>),

    // FRI specific instructions.
    /// Executes a FRI fold operation. 1st field is the size of the fri fold input array.  2nd
    /// field is the fri fold input array.  See [`FriFoldInput`] for more details.
    FriFold(Var<C::N>, Array<C, FriFoldInput<C>>),
    // FRI specific instructions.
    /// Executes a FRI fold operation. Input is the fri fold input array.  See [`FriFoldInput`] for
    /// more details.
    CircuitV2FriFold(Box<(CircuitV2FriFoldOutput<C>, CircuitV2FriFoldInput<C>)>),
    /// Select's a variable based on a condition. (select(cond, true_val, false_val) => output).
    /// Should only be used when target is a gnark circuit.
    CircuitSelectV(Var<C::N>, Var<C::N>, Var<C::N>, Var<C::N>),
    /// Select's a field element based on a condition. (select(cond, true_val, false_val) =>
    /// output). Should only be used when target is a gnark circuit.
    CircuitSelectF(Var<C::N>, Felt<C::F>, Felt<C::F>, Felt<C::F>),
    /// Select's an extension field element based on a condition. (select(cond, true_val,
    /// false_val) => output). Should only be used when target is a gnark circuit.
    CircuitSelectE(Var<C::N>, Ext<C::F, C::EF>, Ext<C::F, C::EF>, Ext<C::F, C::EF>),
    /// Converts an ext to a slice of felts. Should only be used when target is a gnark circuit.
    CircuitExt2Felt([Felt<C::F>; 4], Ext<C::F, C::EF>),
    /// Converts a slice of felts to an ext. Should only be used when target is a gnark circuit.
    CircuitFelts2Ext([Felt<C::F>; 4], Ext<C::F, C::EF>),

    // Debugging instructions.
    /// Executes less than (var = var < var).  This operation is NOT constrained.
    LessThan(Var<C::N>, Var<C::N>, Var<C::N>),
    /// Tracks the number of cycles used by a block of code annotated by the string input.
    CycleTracker(String),
    /// Tracks the number of cycles used by a block of code annotated by the string input.
    CycleTrackerV2Enter(String),
    /// Tracks the number of cycles used by a block of code annotated by the string input.
    CycleTrackerV2Exit,

    // Reverse bits exponentiation.
    ExpReverseBitsLen(Ptr<C::N>, Var<C::N>, Var<C::N>),
    /// Reverse bits exponentiation. Output, base, exponent bits.
    CircuitV2ExpReverseBits(Felt<C::F>, Felt<C::F>, Vec<Felt<C::F>>),
}
