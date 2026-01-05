//! R1CS Compiler - compiles DslIr directly to R1CS matrices.
//!
//! This is the core compiler that converts SP1's recursion IR to R1CS constraints.
//! Each opcode is carefully lowered to preserve the semantic equivalence with
//! SP1's native execution.

use p3_field::{AbstractExtensionField, AbstractField, PrimeField64};
use std::collections::HashMap;

use crate::ir::{Config, DslIr, Ext};
use super::types::{R1CS, SparseRow};
use super::poseidon2::Poseidon2R1CS;

/// The BabyBear prime modulus
#[allow(dead_code)]
const BABYBEAR_P: u64 = 2013265921;

/// R1CS Compiler state
pub struct R1CSCompiler<C: Config> {
    /// The R1CS being constructed
    pub r1cs: R1CS<C::F>,
    /// Mapping from DSL variable IDs to R1CS indices
    pub var_map: HashMap<String, usize>,
    /// Next available variable index
    pub next_var: usize,
    /// Public input indices
    pub public_inputs: Vec<usize>,
    /// Witness input indices (for witness opcodes)
    pub witness_felts: Vec<usize>,
    pub witness_exts: Vec<usize>,
    pub witness_vars: Vec<usize>,
    /// VkeyHash index (public)
    pub vkey_hash_idx: Option<usize>,
    /// CommittedValuesDigest index (public)
    pub committed_values_digest_idx: Option<usize>,
}

impl<C: Config> R1CSCompiler<C>
where
    C::F: PrimeField64,
{
    pub fn new() -> Self {
        let mut compiler = Self {
            r1cs: R1CS::new(),
            var_map: HashMap::new(),
            next_var: 1, // Index 0 is reserved for constant 1
            public_inputs: Vec::new(),
            witness_felts: Vec::new(),
            witness_exts: Vec::new(),
            witness_vars: Vec::new(),
            vkey_hash_idx: None,
            committed_values_digest_idx: None,
        };
        compiler.r1cs.num_vars = 1;
        compiler
    }

    /// Allocate a new variable and return its index
    fn alloc_var(&mut self) -> usize {
        let idx = self.next_var;
        self.next_var += 1;
        self.r1cs.num_vars = self.next_var;
        idx
    }

    /// Get or allocate variable for a DSL variable ID
    fn get_or_alloc(&mut self, id: &str) -> usize {
        if let Some(&idx) = self.var_map.get(id) {
            idx
        } else {
            let idx = self.alloc_var();
            self.var_map.insert(id.to_string(), idx);
            idx
        }
    }

    /// Get existing variable index, or allocate if not found.
    /// 
    /// NOTE: We allow forward references (using a variable before it's "declared") because
    /// the SP1 verifier IR can reference variables that are declared later via hint ops.
    /// This matches the behavior of the circuit compiler's `Entry::Vacant` pattern.
    fn get_var(&mut self, id: &str) -> usize {
        if let Some(&idx) = self.var_map.get(id) {
            idx
        } else {
            // Forward reference - allocate the variable
            let idx = self.alloc_var();
            self.var_map.insert(id.to_string(), idx);
            idx
        }
    }

    /// Allocate a constant and return its index
    fn alloc_const(&mut self, value: C::F) -> usize {
        let idx = self.alloc_var();
        // Constraint: idx = value (using constant 1 at index 0)
        // (1) * (value) = (idx)
        self.r1cs.add_constraint(
            SparseRow::single(0), // A: 1
            SparseRow::constant(value), // B: value
            SparseRow::single(idx), // C: idx
        );
        idx
    }

    /// Add multiplication constraint: out = a * b
    fn add_mul(&mut self, out: usize, a: usize, b: usize) {
        self.r1cs.add_constraint(
            SparseRow::single(a),
            SparseRow::single(b),
            SparseRow::single(out),
        );
    }

    /// Add equality constraint: a = b
    /// Encoded as: (a - b) * 1 = 0
    fn add_eq(&mut self, a: usize, b: usize) {
        let mut a_row = SparseRow::new();
        a_row.add_term(a, C::F::one());
        a_row.add_term(b, -C::F::one());
        self.r1cs.add_constraint(
            a_row,
            SparseRow::single(0), // B: 1
            SparseRow::zero(), // C: 0
        );
    }

    /// Add constraint: a != b (via inverse hint)
    /// We compute diff = a - b, then prove diff has an inverse
    /// diff_inv is hinted, and we check diff * diff_inv = 1
    fn add_neq(&mut self, a: usize, b: usize) {
        // diff = a - b (linear, allocated as witness)
        let diff = self.alloc_var();
        // diff_inv = 1/(a-b) (hinted)
        let diff_inv = self.alloc_var();
        
        // Constraint: diff = a - b
        // (1) * (a - b) = diff
        let mut ab_diff = SparseRow::new();
        ab_diff.add_term(a, C::F::one());
        ab_diff.add_term(b, -C::F::one());
        self.r1cs.add_constraint(
            SparseRow::single(0),
            ab_diff,
            SparseRow::single(diff),
        );
        
        // Constraint: diff * diff_inv = 1
        self.r1cs.add_constraint(
            SparseRow::single(diff),
            SparseRow::single(diff_inv),
            SparseRow::single(0), // C: constant 1
        );
    }

    /// Add boolean constraint: b * (1 - b) = 0
    /// This ensures b ∈ {0, 1}
    fn add_boolean(&mut self, b: usize) {
        // b * (1 - b) = 0
        // A: b, B: (1 - b), C: 0
        let mut one_minus_b = SparseRow::new();
        one_minus_b.add_term(0, C::F::one()); // 1
        one_minus_b.add_term(b, -C::F::one()); // - b
        self.r1cs.add_constraint(
            SparseRow::single(b),
            one_minus_b,
            SparseRow::zero(),
        );
    }

    /// Add select constraint: out = cond ? a : b
    /// Encoded as: out = cond * (a - b) + b
    /// Which is: out - b = cond * (a - b)
    /// R1CS: (cond) * (a - b) = (out - b)
    /// 
    /// IMPORTANT: Also adds boolean constraint on cond!
    fn add_select(&mut self, out: usize, cond: usize, a: usize, b: usize) {
        // First ensure cond is boolean
        self.add_boolean(cond);
        
        // (cond) * (a - b) = (out - b)
        let mut a_minus_b = SparseRow::new();
        a_minus_b.add_term(a, C::F::one());
        a_minus_b.add_term(b, -C::F::one());
        
        let mut out_minus_b = SparseRow::new();
        out_minus_b.add_term(out, C::F::one());
        out_minus_b.add_term(b, -C::F::one());
        
        self.r1cs.add_constraint(
            SparseRow::single(cond),
            a_minus_b,
            out_minus_b,
        );
    }

    /// Add bit decomposition constraints: value = sum(bits[i] * 2^i)
    /// Also adds boolean constraints on each bit
    fn add_num2bits(&mut self, value: usize, bits: &[usize], num_bits: usize) {
        // Each bit must be boolean
        for &bit in bits.iter().take(num_bits) {
            self.add_boolean(bit);
        }
        
        // value = sum(bits[i] * 2^i)
        // We express this as: (1) * (sum) = (value)
        let mut sum = SparseRow::new();
        let mut power = C::F::one();
        let two = C::F::from_canonical_u64(2);
        for &bit in bits.iter().take(num_bits) {
            sum.add_term(bit, power);
            power = power * two;
        }
        
        self.r1cs.add_constraint(
            SparseRow::single(0), // A: 1
            sum, // B: sum of bits
            SparseRow::single(value), // C: value
        );
    }

    /// Compile a single DSL instruction to R1CS constraints
    pub fn compile_one(&mut self, instr: DslIr<C>) {
        match instr {
            // === Immediate values ===
            DslIr::ImmV(_dst, _val) => {
                // NOTE: This backend targets BabyBear-native shrink verifier work.
                // `ImmV` operates over `C::N` (Var field), which is not guaranteed to equal `C::F`.
                // Silently allocating would create an unconstrained variable.
                panic!("R1CSCompiler: ImmV not supported (Var field C::N may differ from C::F). Implement Var-field support or restrict Config so C::N == C::F.");
            }
            
            DslIr::ImmF(dst, val) => {
                let dst_idx = self.get_or_alloc(&dst.id());
                let const_idx = self.alloc_const(val);
                self.add_eq(dst_idx, const_idx);
            }
            
            DslIr::ImmE(dst, val) => {
                // Extension element: 4 base field elements
                let base = val.as_base_slice();
                for (i, &coeff) in base.iter().enumerate() {
                    let dst_idx = self.get_or_alloc(&format!("{}__{}", dst.id(), i));
                    let const_idx = self.alloc_const(coeff);
                    self.add_eq(dst_idx, const_idx);
                }
            }

            // === Addition (linear, no constraint needed - just track wiring) ===
            DslIr::AddV(dst, lhs, rhs) => {
                let dst_idx = self.get_or_alloc(&dst.id());
                let lhs_idx = self.get_var(&lhs.id());
                let rhs_idx = self.get_var(&rhs.id());
                
                let mut sum = SparseRow::new();
                sum.add_term(lhs_idx, C::F::one());
                sum.add_term(rhs_idx, C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    sum,
                    SparseRow::single(dst_idx),
                );
            }
            
            DslIr::AddF(dst, lhs, rhs) => {
                let dst_idx = self.get_or_alloc(&dst.id());
                let lhs_idx = self.get_var(&lhs.id());
                let rhs_idx = self.get_var(&rhs.id());
                
                let mut sum = SparseRow::new();
                sum.add_term(lhs_idx, C::F::one());
                sum.add_term(rhs_idx, C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    sum,
                    SparseRow::single(dst_idx),
                );
            }
            
            DslIr::AddVI(_dst, _lhs, _rhs) => {
                // NOTE: This backend targets BabyBear-native shrink verifier work.
                // `AddVI` operates over `C::N` (Var field), which is not guaranteed to equal `C::F`.
                // Silently skipping would create unconstrained variables, so we fail fast.
                panic!("R1CSCompiler: AddVI not supported (Var field C::N may differ from C::F). Implement Var-field support or restrict Config so C::N == C::F.");
            }
            
            DslIr::AddFI(dst, lhs, rhs) => {
                let dst_idx = self.get_or_alloc(&dst.id());
                let lhs_idx = self.get_var(&lhs.id());
                let const_idx = self.alloc_const(rhs);
                
                let mut sum = SparseRow::new();
                sum.add_term(lhs_idx, C::F::one());
                sum.add_term(const_idx, C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    sum,
                    SparseRow::single(dst_idx),
                );
            }

            // === Subtraction ===
            DslIr::SubV(dst, lhs, rhs) => {
                let dst_idx = self.get_or_alloc(&dst.id());
                let lhs_idx = self.get_var(&lhs.id());
                let rhs_idx = self.get_var(&rhs.id());
                
                let mut diff = SparseRow::new();
                diff.add_term(lhs_idx, C::F::one());
                diff.add_term(rhs_idx, -C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    diff,
                    SparseRow::single(dst_idx),
                );
            }
            
            DslIr::SubF(dst, lhs, rhs) => {
                let dst_idx = self.get_or_alloc(&dst.id());
                let lhs_idx = self.get_var(&lhs.id());
                let rhs_idx = self.get_var(&rhs.id());
                
                let mut diff = SparseRow::new();
                diff.add_term(lhs_idx, C::F::one());
                diff.add_term(rhs_idx, -C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    diff,
                    SparseRow::single(dst_idx),
                );
            }
            
            DslIr::SubFI(dst, lhs, rhs) => {
                let dst_idx = self.get_or_alloc(&dst.id());
                let lhs_idx = self.get_var(&lhs.id());
                let const_idx = self.alloc_const(rhs);
                
                let mut diff = SparseRow::new();
                diff.add_term(lhs_idx, C::F::one());
                diff.add_term(const_idx, -C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    diff,
                    SparseRow::single(dst_idx),
                );
            }
            
            DslIr::SubFIN(dst, lhs, rhs) => {
                // dst = lhs (constant) - rhs (variable)
                let dst_idx = self.get_or_alloc(&dst.id());
                let rhs_idx = self.get_var(&rhs.id());
                let const_idx = self.alloc_const(lhs);
                
                let mut diff = SparseRow::new();
                diff.add_term(const_idx, C::F::one());
                diff.add_term(rhs_idx, -C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    diff,
                    SparseRow::single(dst_idx),
                );
            }

            // === Multiplication ===
            DslIr::MulV(dst, lhs, rhs) => {
                let dst_idx = self.get_or_alloc(&dst.id());
                let lhs_idx = self.get_var(&lhs.id());
                let rhs_idx = self.get_var(&rhs.id());
                self.add_mul(dst_idx, lhs_idx, rhs_idx);
            }
            
            DslIr::MulF(dst, lhs, rhs) => {
                let dst_idx = self.get_or_alloc(&dst.id());
                let lhs_idx = self.get_var(&lhs.id());
                let rhs_idx = self.get_var(&rhs.id());
                self.add_mul(dst_idx, lhs_idx, rhs_idx);
            }
            
            DslIr::MulVI(_dst, _lhs, _rhs) => {
                panic!("R1CSCompiler: MulVI not supported (Var field C::N may differ from C::F). Implement Var-field support or restrict Config so C::N == C::F.");
            }
            
            DslIr::MulFI(dst, lhs, rhs) => {
                let dst_idx = self.get_or_alloc(&dst.id());
                let lhs_idx = self.get_var(&lhs.id());
                let const_idx = self.alloc_const(rhs);
                self.add_mul(dst_idx, lhs_idx, const_idx);
            }

            // === Division (via inverse hint) ===
            DslIr::DivF(dst, lhs, rhs) => {
                let dst_idx = self.get_or_alloc(&dst.id());
                let lhs_idx = self.get_var(&lhs.id());
                let rhs_idx = self.get_var(&rhs.id());
                
                // dst = lhs / rhs
                // Constraint: dst * rhs = lhs
                self.r1cs.add_constraint(
                    SparseRow::single(dst_idx),
                    SparseRow::single(rhs_idx),
                    SparseRow::single(lhs_idx),
                );
            }
            
            DslIr::DivFI(dst, lhs, rhs) => {
                let dst_idx = self.get_or_alloc(&dst.id());
                let lhs_idx = self.get_var(&lhs.id());
                let const_idx = self.alloc_const(rhs);
                
                self.r1cs.add_constraint(
                    SparseRow::single(dst_idx),
                    SparseRow::single(const_idx),
                    SparseRow::single(lhs_idx),
                );
            }
            
            DslIr::DivFIN(dst, lhs, rhs) => {
                let dst_idx = self.get_or_alloc(&dst.id());
                let const_idx = self.alloc_const(lhs);
                let rhs_idx = self.get_var(&rhs.id());
                
                self.r1cs.add_constraint(
                    SparseRow::single(dst_idx),
                    SparseRow::single(rhs_idx),
                    SparseRow::single(const_idx),
                );
            }

            // === Negation ===
            DslIr::NegV(dst, src) => {
                let dst_idx = self.get_or_alloc(&dst.id());
                let src_idx = self.get_var(&src.id());
                
                let mut neg_src = SparseRow::new();
                neg_src.add_term(src_idx, -C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    neg_src,
                    SparseRow::single(dst_idx),
                );
            }
            
            DslIr::NegF(dst, src) => {
                let dst_idx = self.get_or_alloc(&dst.id());
                let src_idx = self.get_var(&src.id());
                
                let mut neg_src = SparseRow::new();
                neg_src.add_term(src_idx, -C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    neg_src,
                    SparseRow::single(dst_idx),
                );
            }

            // === Inversion ===
            DslIr::InvV(dst, src) => {
                let dst_idx = self.get_or_alloc(&dst.id());
                let src_idx = self.get_var(&src.id());
                
                // dst = 1 / src
                // Constraint: dst * src = 1
                self.r1cs.add_constraint(
                    SparseRow::single(dst_idx),
                    SparseRow::single(src_idx),
                    SparseRow::single(0), // constant 1
                );
            }
            
            DslIr::InvF(dst, src) => {
                let dst_idx = self.get_or_alloc(&dst.id());
                let src_idx = self.get_var(&src.id());
                
                self.r1cs.add_constraint(
                    SparseRow::single(dst_idx),
                    SparseRow::single(src_idx),
                    SparseRow::single(0), // constant 1
                );
            }

            // === Assertions ===
            DslIr::AssertEqV(lhs, rhs) => {
                let lhs_idx = self.get_var(&lhs.id());
                let rhs_idx = self.get_var(&rhs.id());
                self.add_eq(lhs_idx, rhs_idx);
            }
            
            DslIr::AssertEqF(lhs, rhs) => {
                let lhs_idx = self.get_var(&lhs.id());
                let rhs_idx = self.get_var(&rhs.id());
                self.add_eq(lhs_idx, rhs_idx);
            }
            
            DslIr::AssertEqVI(_lhs, _rhs) => {
                panic!("R1CSCompiler: AssertEqVI not supported (Var field C::N may differ from C::F). Implement Var-field support or restrict Config so C::N == C::F.");
            }
            
            DslIr::AssertEqFI(lhs, rhs) => {
                let lhs_idx = self.get_var(&lhs.id());
                let const_idx = self.alloc_const(rhs);
                self.add_eq(lhs_idx, const_idx);
            }
            
            DslIr::AssertNeV(lhs, rhs) => {
                let lhs_idx = self.get_var(&lhs.id());
                let rhs_idx = self.get_var(&rhs.id());
                self.add_neq(lhs_idx, rhs_idx);
            }
            
            DslIr::AssertNeF(lhs, rhs) => {
                let lhs_idx = self.get_var(&lhs.id());
                let rhs_idx = self.get_var(&rhs.id());
                self.add_neq(lhs_idx, rhs_idx);
            }
            
            DslIr::AssertNeVI(_lhs, _rhs) => {
                panic!("R1CSCompiler: AssertNeVI not supported (Var field C::N may differ from C::F). Implement Var-field support or restrict Config so C::N == C::F.");
            }
            
            DslIr::AssertNeFI(lhs, rhs) => {
                let lhs_idx = self.get_var(&lhs.id());
                let const_idx = self.alloc_const(rhs);
                self.add_neq(lhs_idx, const_idx);
            }

            // === Select operations ===
            DslIr::CircuitSelectV(cond, a, b, out) => {
                let out_idx = self.get_or_alloc(&out.id());
                let cond_idx = self.get_var(&cond.id());
                let a_idx = self.get_var(&a.id());
                let b_idx = self.get_var(&b.id());
                self.add_select(out_idx, cond_idx, a_idx, b_idx);
            }
            
            DslIr::CircuitSelectF(cond, a, b, out) => {
                let out_idx = self.get_or_alloc(&out.id());
                let cond_idx = self.get_var(&cond.id());
                let a_idx = self.get_var(&a.id());
                let b_idx = self.get_var(&b.id());
                self.add_select(out_idx, cond_idx, a_idx, b_idx);
            }

            // === Bit decomposition ===
            DslIr::CircuitNum2BitsV(value, num_bits, output) => {
                let value_idx = self.get_var(&value.id());
                let bit_indices: Vec<usize> = output
                    .iter()
                    .map(|v| self.get_or_alloc(&v.id()))
                    .collect();
                self.add_num2bits(value_idx, &bit_indices, num_bits);
            }
            
            DslIr::CircuitNum2BitsF(value, output) => {
                let value_idx = self.get_var(&value.id());
                let bit_indices: Vec<usize> = output
                    .iter()
                    .map(|v| self.get_or_alloc(&v.id()))
                    .collect();
                // BabyBear has 31-bit modulus
                self.add_num2bits(value_idx, &bit_indices, 31);
            }

            // === Poseidon2 permutation (BabyBear) - V2 with separate input/output ===
            DslIr::CircuitV2Poseidon2PermuteBabyBear(boxed) => {
                let (input, output) = boxed.as_ref();
                
                // Get input variable indices
                let input_indices: Vec<usize> = (0..16)
                    .map(|i| self.get_var(&input[i].id()))
                    .collect();
                
                // Allocate output variable indices
                let output_indices: Vec<usize> = (0..16)
                    .map(|i| self.get_or_alloc(&output[i].id()))
                    .collect();
                
                // Expand Poseidon2 and get computed output indices
                let computed_output = Poseidon2R1CS::<C::F>::expand_permute_babybear(
                    &mut self.r1cs,
                    &mut self.next_var,
                    &input_indices,
                );
                
                // Bind computed outputs to the declared output variables
                for i in 0..16 {
                    self.add_eq(output_indices[i], computed_output[i]);
                }
            }
            
            // === Poseidon2 permutation (BabyBear) - in-place variant (gnark) ===
            DslIr::CircuitPoseidon2PermuteBabyBear(state) => {
                let state_indices: Vec<usize> = (0..16)
                    .map(|i| self.get_var(&state[i].id()))
                    .collect();
                
                // For in-place variant, computed output overwrites input
                let computed_output = Poseidon2R1CS::<C::F>::expand_permute_babybear(
                    &mut self.r1cs,
                    &mut self.next_var,
                    &state_indices,
                );
                
                // Update the variable map to point to the new output indices
                for i in 0..16 {
                    self.var_map.insert(state[i].id(), computed_output[i]);
                }
            }
            
            // === BN254 Poseidon2 (for outer wrap - not used for Symphony) ===
            DslIr::CircuitPoseidon2Permute(_state) => {
                // This is for BN254 outer wrap, skip for BabyBear R1CS
                panic!("CircuitPoseidon2Permute (BN254) not supported in BabyBear R1CS backend");
            }
            
            // === Select (conditional swap) ===
            // Select(should_swap, first_result, second_result, first_input, second_input)
            // If should_swap == 1: first_result = second_input, second_result = first_input
            // If should_swap == 0: first_result = first_input, second_result = second_input
            DslIr::Select(should_swap, first_result, second_result, first_input, second_input) => {
                let swap_idx = self.get_var(&should_swap.id());
                let out1_idx = self.get_or_alloc(&first_result.id());
                let out2_idx = self.get_or_alloc(&second_result.id());
                let in1_idx = self.get_var(&first_input.id());
                let in2_idx = self.get_var(&second_input.id());
                
                // Ensure should_swap is boolean
                self.add_boolean(swap_idx);
                
                // first_result = should_swap * second_input + (1 - should_swap) * first_input
                //              = should_swap * (second_input - first_input) + first_input
                // R1CS: (swap) * (in2 - in1) = (out1 - in1)
                let mut in2_minus_in1 = SparseRow::new();
                in2_minus_in1.add_term(in2_idx, C::F::one());
                in2_minus_in1.add_term(in1_idx, -C::F::one());
                
                let mut out1_minus_in1 = SparseRow::new();
                out1_minus_in1.add_term(out1_idx, C::F::one());
                out1_minus_in1.add_term(in1_idx, -C::F::one());
                
                self.r1cs.add_constraint(
                    SparseRow::single(swap_idx),
                    in2_minus_in1,
                    out1_minus_in1,
                );
                
                // second_result = should_swap * first_input + (1 - should_swap) * second_input
                //               = should_swap * (first_input - second_input) + second_input
                // R1CS: (swap) * (in1 - in2) = (out2 - in2)
                let mut in1_minus_in2 = SparseRow::new();
                in1_minus_in2.add_term(in1_idx, C::F::one());
                in1_minus_in2.add_term(in2_idx, -C::F::one());
                
                let mut out2_minus_in2 = SparseRow::new();
                out2_minus_in2.add_term(out2_idx, C::F::one());
                out2_minus_in2.add_term(in2_idx, -C::F::one());
                
                self.r1cs.add_constraint(
                    SparseRow::single(swap_idx),
                    in1_minus_in2,
                    out2_minus_in2,
                );
            }
            
            // === V2 Hint operations (witness inputs for shrink verifier) ===
            //
            // NOTE: `CircuitV2HintFelts(start, len)` and `CircuitV2HintExts(start, len)` are
            // *contiguous ranges* of memory locations. The witness stream is consumed in *program
            // order*, so we record these as an ordered list (append), not by indexing into an array.
            DslIr::CircuitV2HintFelts(start, len) => {
                for i in 0..len {
                    let id = format!("felt{}", start.idx + i as u32);
                    let felt_idx = self.get_or_alloc(&id);
                    self.witness_felts.push(felt_idx);
                }
            }

            DslIr::CircuitV2HintExts(start, len) => {
                for j in 0..len {
                    let ext_id = format!("ext{}", start.idx + j as u32);
                    for limb in 0..4 {
                        let component_id = format!("{}__{}", ext_id, limb);
                        let ext_idx = self.get_or_alloc(&component_id);
                        self.witness_exts.push(ext_idx);
                    }
                }
            }
            
            DslIr::CircuitV2HintBitsF(bits, value) => {
                let value_idx = self.get_var(&value.id());
                let bit_indices: Vec<usize> = bits
                    .iter()
                    .map(|b| self.get_or_alloc(&b.id()))
                    .collect();
                // Soundness note:
                // BabyBear elements have a unique canonical representative in [0, p-1) with
                // p < 2^31, so a bit decomposition must use at most 31 bits.
                //
                // If the IR ever asked for >31 bits and we only constrained the low 31, the
                // remaining bits would be unconstrained witness degrees of freedom.
                let nbits = bit_indices.len();
                assert!(
                    nbits <= 31,
                    "CircuitV2HintBitsF: requested {nbits} bits for a BabyBear Felt; this would be non-canonical/unsound. Expected <= 31."
                );
                self.add_num2bits(value_idx, &bit_indices, nbits);
            }

            // === FRI operations ===
            //
            // CircuitV2FriFold: For each element i in the batch:
            //   alpha_pow_output[i] = alpha_pow_input[i] * alpha
            //   (ro_output[i] - ro_input[i]) * (z - x) = alpha_pow_input[i] * (mat_opening[i] - ps_at_z[i])
            DslIr::CircuitV2FriFold(boxed) => {
                let (output, input) = boxed.as_ref();
                let n = input.mat_opening.len();
                
                // Get input indices
                let z_idx: Vec<usize> = (0..4).map(|i| self.get_var(&format!("{}__{}", input.z.id(), i))).collect();
                let alpha_idx: Vec<usize> = (0..4).map(|i| self.get_var(&format!("{}__{}", input.alpha.id(), i))).collect();
                let x_idx = self.get_var(&input.x.id());
                
                 for j in 0..n {
                    // Get input arrays
                    let mat_opening_idx: Vec<usize> = (0..4).map(|i| self.get_var(&format!("{}__{}", input.mat_opening[j].id(), i))).collect();
                    let ps_at_z_idx: Vec<usize> = (0..4).map(|i| self.get_var(&format!("{}__{}", input.ps_at_z[j].id(), i))).collect();
                    let alpha_pow_in_idx: Vec<usize> = (0..4).map(|i| self.get_var(&format!("{}__{}", input.alpha_pow_input[j].id(), i))).collect();
                    let ro_in_idx: Vec<usize> = (0..4).map(|i| self.get_var(&format!("{}__{}", input.ro_input[j].id(), i))).collect();
                    
                    // Allocate outputs
                    let alpha_pow_out_idx: Vec<usize> = (0..4).map(|i| self.get_or_alloc(&format!("{}__{}", output.alpha_pow_output[j].id(), i))).collect();
                    let ro_out_idx: Vec<usize> = (0..4).map(|i| self.get_or_alloc(&format!("{}__{}", output.ro_output[j].id(), i))).collect();
                    
                    // Constraint 1: alpha_pow_output = alpha_pow_input * alpha
                    // This is extension multiplication
                    self.compile_ext_mul_from_indices(&alpha_pow_out_idx, &alpha_pow_in_idx, &alpha_idx);
                    
                     // Constraint 2 (matches recursion-core FriFoldChip):
                     //   (new_ro - old_ro) * (x - z) = (p_at_x - p_at_z) * old_alpha_pow
                     // where:
                     //   p_at_x := mat_opening[j]
                     //   p_at_z := ps_at_z[j]
                     //
                     // See `sp1/crates/recursion/core/src/chips/fri_fold.rs`:
                     //   (new_ro - old_ro) * (BinomialExtension::from_base(x) - z)
                     //     = (p_at_x - p_at_z) * old_alpha_pow
                    // Let diff_ro = ro_output - ro_input
                    // Let diff_p = mat_opening - ps_at_z
                    // Let z_minus_x = z - x (extension - felt, only affects first component)
                    // Then: diff_ro * z_minus_x = alpha_pow_input * diff_p
                    
                    // Compute diff_p = mat_opening - ps_at_z
                    let diff_p_idx: Vec<usize> = (0..4).map(|_| self.alloc_var()).collect();
                    for i in 0..4 {
                        let mut diff = SparseRow::new();
                        diff.add_term(mat_opening_idx[i], C::F::one());
                        diff.add_term(ps_at_z_idx[i], -C::F::one());
                        self.r1cs.add_constraint(
                            SparseRow::single(0),
                            diff,
                            SparseRow::single(diff_p_idx[i]),
                        );
                    }
                    
                    // Compute rhs = alpha_pow_input * diff_p
                    let rhs_idx: Vec<usize> = (0..4).map(|_| self.alloc_var()).collect();
                    self.compile_ext_mul_from_indices(&rhs_idx, &alpha_pow_in_idx, &diff_p_idx);
                    
                    // Compute diff_ro = ro_output - ro_input
                    let diff_ro_idx: Vec<usize> = (0..4).map(|_| self.alloc_var()).collect();
                    for i in 0..4 {
                        let mut diff = SparseRow::new();
                        diff.add_term(ro_out_idx[i], C::F::one());
                        diff.add_term(ro_in_idx[i], -C::F::one());
                        self.r1cs.add_constraint(
                            SparseRow::single(0),
                            diff,
                            SparseRow::single(diff_ro_idx[i]),
                        );
                    }
                    
                     // Compute x_minus_z = (x - z) = BinomialExtension::from_base(x) - z.
                     // First component: x - z[0]
                     // Other components: -z[i]
                     let x_minus_z_idx: Vec<usize> = (0..4).map(|_| self.alloc_var()).collect();
                     let mut xmz0 = SparseRow::new();
                     xmz0.add_term(x_idx, C::F::one());
                     xmz0.add_term(z_idx[0], -C::F::one());
                     self.r1cs.add_constraint(
                         SparseRow::single(0),
                         xmz0,
                         SparseRow::single(x_minus_z_idx[0]),
                     );
                     for i in 1..4 {
                         let mut neg = SparseRow::new();
                         neg.add_term(z_idx[i], -C::F::one());
                         self.r1cs.add_constraint(
                             SparseRow::single(0),
                             neg,
                             SparseRow::single(x_minus_z_idx[i]),
                         );
                     }
                    
                     // Constraint: diff_ro * x_minus_z = rhs
                    // This is extension multiplication check
                     self.compile_ext_mul_check_from_indices(&diff_ro_idx, &x_minus_z_idx, &rhs_idx);
                }
            }
            
            // CircuitV2BatchFRI: Compute acc = sum(alpha_pows[i] * (p_at_zs[i] - p_at_xs[i]))
            DslIr::CircuitV2BatchFRI(boxed) => {
                let (acc, alpha_pows, p_at_zs, p_at_xs) = boxed.as_ref();
                let n = alpha_pows.len();
                
                // Allocate output accumulator
                let acc_idx: Vec<usize> = (0..4).map(|i| self.get_or_alloc(&format!("{}__{}", acc.id(), i))).collect();
                
                // Start with zero
                let mut running_sum_idx: Vec<usize> = (0..4).map(|_| {
                    let idx = self.alloc_var();
                    // Initialize to zero via constraint: 1 * 0 = idx
                    self.r1cs.add_constraint(
                        SparseRow::single(0),
                        SparseRow::zero(),
                        SparseRow::single(idx),
                    );
                    idx
                }).collect();
                
                for j in 0..n {
                    // Get alpha_pow[j]
                    let alpha_pow_idx: Vec<usize> = (0..4).map(|i| self.get_var(&format!("{}__{}", alpha_pows[j].id(), i))).collect();
                    
                    // Get p_at_z[j]
                    let p_at_z_idx: Vec<usize> = (0..4).map(|i| self.get_var(&format!("{}__{}", p_at_zs[j].id(), i))).collect();
                    
                    // Get p_at_x[j] (this is a Felt, so it's just one component embedded in ext)
                    let p_at_x_idx = self.get_var(&p_at_xs[j].id());
                    
                    // Compute diff = p_at_z - p_at_x (ext - felt)
                    let diff_idx: Vec<usize> = (0..4).map(|_| self.alloc_var()).collect();
                    // First component: p_at_z[0] - p_at_x
                    let mut diff0 = SparseRow::new();
                    diff0.add_term(p_at_z_idx[0], C::F::one());
                    diff0.add_term(p_at_x_idx, -C::F::one());
                    self.r1cs.add_constraint(
                        SparseRow::single(0),
                        diff0,
                        SparseRow::single(diff_idx[0]),
                    );
                    // Other components: p_at_z[i]
                    for i in 1..4 {
                        self.add_eq(diff_idx[i], p_at_z_idx[i]);
                    }
                    
                    // Compute term = alpha_pow * diff
                    let term_idx: Vec<usize> = (0..4).map(|_| self.alloc_var()).collect();
                    self.compile_ext_mul_from_indices(&term_idx, &alpha_pow_idx, &diff_idx);
                    
                    // Add to running sum: new_sum = running_sum + term
                    let new_sum_idx: Vec<usize> = (0..4).map(|_| self.alloc_var()).collect();
                    for i in 0..4 {
                        let mut sum = SparseRow::new();
                        sum.add_term(running_sum_idx[i], C::F::one());
                        sum.add_term(term_idx[i], C::F::one());
                        self.r1cs.add_constraint(
                            SparseRow::single(0),
                            sum,
                            SparseRow::single(new_sum_idx[i]),
                        );
                    }
                    running_sum_idx = new_sum_idx;
                }
                
                // Bind final sum to output accumulator
                for i in 0..4 {
                    self.add_eq(acc_idx[i], running_sum_idx[i]);
                }
            }
            
             // CircuitV2ExpReverseBits: exponentiation driven by a bit stream.
             //
             // We match the recursion-core ExpReverseBitsLen chip recurrence:
             //   accum_0 = 1
             //   for bit in bits:
             //     multiplier = if bit==1 { base } else { 1 }
             //     accum = accum^2 * multiplier
             //
             // This avoids ambiguity about "reverse" ordering and matches the chip semantics
             // for the provided bit sequence.
            DslIr::CircuitV2ExpReverseBits(output, base, bits) => {
                let output_idx = self.get_or_alloc(&output.id());
                let base_idx = self.get_var(&base.id());
                let bit_indices: Vec<usize> = bits.iter().map(|b| self.get_var(&b.id())).collect();
                 
                 // accum starts at 1 (constant witness slot 0).
                 let mut accum_idx: usize = 0;
                 for bit_idx in bit_indices {
                     // Ensure bit is boolean.
                     self.add_boolean(bit_idx);
                     
                     // accum_sq = accum * accum
                     let accum_sq = self.alloc_var();
                     self.add_mul(accum_sq, accum_idx, accum_idx);
                     
                     // multiplier = bit ? base : 1
                     // Encode: (bit) * (base - 1) = (multiplier - 1)
                     let multiplier = self.alloc_var();
                     let mut base_minus_one = SparseRow::new();
                     base_minus_one.add_term(base_idx, C::F::one());
                     base_minus_one.add_term(0, -C::F::one()); // subtract 1
                     let mut mult_minus_one = SparseRow::new();
                     mult_minus_one.add_term(multiplier, C::F::one());
                     mult_minus_one.add_term(0, -C::F::one()); // subtract 1
                     self.r1cs.add_constraint(
                         SparseRow::single(bit_idx),
                         base_minus_one,
                         mult_minus_one,
                     );
                     
                     // accum_next = accum_sq * multiplier
                     let accum_next = self.alloc_var();
                     self.add_mul(accum_next, accum_sq, multiplier);
                     accum_idx = accum_next;
                 }
                 
                 // Bind final accum to output.
                 self.add_eq(output_idx, accum_idx);
            }

            // === Witness operations ===
            DslIr::WitnessVar(dst, idx) => {
                let dst_idx = self.get_or_alloc(&dst.id());
                // Track that this variable comes from witness
                while self.witness_vars.len() <= idx as usize {
                    self.witness_vars.push(0);
                }
                self.witness_vars[idx as usize] = dst_idx;
            }
            
            DslIr::WitnessFelt(dst, idx) => {
                let dst_idx = self.get_or_alloc(&dst.id());
                while self.witness_felts.len() <= idx as usize {
                    self.witness_felts.push(0);
                }
                self.witness_felts[idx as usize] = dst_idx;
            }
            
            DslIr::WitnessExt(dst, idx) => {
                // Extension elements are 4 field elements
                for i in 0..4 {
                    let component_id = format!("{}__{}", dst.id(), i);
                    let dst_idx = self.get_or_alloc(&component_id);
                    let flat_idx = (idx as usize) * 4 + i;
                    while self.witness_exts.len() <= flat_idx {
                        self.witness_exts.push(0);
                    }
                    self.witness_exts[flat_idx] = dst_idx;
                }
            }

            // === Public input commitments ===
            DslIr::CircuitCommitVkeyHash(var) => {
                let var_idx = self.get_var(&var.id());
                self.vkey_hash_idx = Some(var_idx);
                self.public_inputs.push(var_idx);
            }
            
            DslIr::CircuitCommitCommittedValuesDigest(var) => {
                let var_idx = self.get_var(&var.id());
                self.committed_values_digest_idx = Some(var_idx);
                self.public_inputs.push(var_idx);
            }

            // === Extension field operations ===
            // These need to be expanded to base field operations
            DslIr::AddE(dst, lhs, rhs) => {
                for i in 0..4 {
                    let dst_idx = self.get_or_alloc(&format!("{}__{}", dst.id(), i));
                    let lhs_idx = self.get_var(&format!("{}__{}", lhs.id(), i));
                    let rhs_idx = self.get_var(&format!("{}__{}", rhs.id(), i));
                    
                    let mut sum = SparseRow::new();
                    sum.add_term(lhs_idx, C::F::one());
                    sum.add_term(rhs_idx, C::F::one());
                    self.r1cs.add_constraint(
                        SparseRow::single(0),
                        sum,
                        SparseRow::single(dst_idx),
                    );
                }
            }
            
            DslIr::SubE(dst, lhs, rhs) => {
                for i in 0..4 {
                    let dst_idx = self.get_or_alloc(&format!("{}__{}", dst.id(), i));
                    let lhs_idx = self.get_var(&format!("{}__{}", lhs.id(), i));
                    let rhs_idx = self.get_var(&format!("{}__{}", rhs.id(), i));
                    
                    let mut diff = SparseRow::new();
                    diff.add_term(lhs_idx, C::F::one());
                    diff.add_term(rhs_idx, -C::F::one());
                    self.r1cs.add_constraint(
                        SparseRow::single(0),
                        diff,
                        SparseRow::single(dst_idx),
                    );
                }
            }
            
            DslIr::MulE(dst, lhs, rhs) => {
                // Extension field multiplication: F_p[u]/(u^4 - 11)
                // (a0 + a1*u + a2*u^2 + a3*u^3) * (b0 + b1*u + b2*u^2 + b3*u^3)
                self.compile_ext_mul(&dst, &lhs, &rhs);
            }
            
            DslIr::AddEF(dst, lhs, rhs) => {
                // Add base field element to extension (only affects first component)
                let dst0 = self.get_or_alloc(&format!("{}__{}", dst.id(), 0));
                let lhs0 = self.get_var(&format!("{}__{}", lhs.id(), 0));
                let rhs_idx = self.get_var(&rhs.id());
                
                let mut sum = SparseRow::new();
                sum.add_term(lhs0, C::F::one());
                sum.add_term(rhs_idx, C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    sum,
                    SparseRow::single(dst0),
                );
                
                // Copy other components
                for i in 1..4 {
                    let dst_i = self.get_or_alloc(&format!("{}__{}", dst.id(), i));
                    let lhs_i = self.get_var(&format!("{}__{}", lhs.id(), i));
                    self.add_eq(dst_i, lhs_i);
                }
            }
            
            DslIr::MulEF(dst, lhs, rhs) => {
                // Multiply extension by base field element
                for i in 0..4 {
                    let dst_idx = self.get_or_alloc(&format!("{}__{}", dst.id(), i));
                    let lhs_idx = self.get_var(&format!("{}__{}", lhs.id(), i));
                    let rhs_idx = self.get_var(&rhs.id());
                    self.add_mul(dst_idx, lhs_idx, rhs_idx);
                }
            }
            
            // === Additional extension field operations with immediates ===
            DslIr::AddEI(dst, lhs, rhs) => {
                // Add extension + extension immediate
                let rhs_base = rhs.as_base_slice();
                for i in 0..4 {
                    let dst_idx = self.get_or_alloc(&format!("{}__{}", dst.id(), i));
                    let lhs_idx = self.get_var(&format!("{}__{}", lhs.id(), i));
                    let const_idx = self.alloc_const(rhs_base[i]);
                    
                    let mut sum = SparseRow::new();
                    sum.add_term(lhs_idx, C::F::one());
                    sum.add_term(const_idx, C::F::one());
                    self.r1cs.add_constraint(
                        SparseRow::single(0),
                        sum,
                        SparseRow::single(dst_idx),
                    );
                }
            }
            
            DslIr::AddEFI(dst, lhs, rhs) => {
                // Add extension + field immediate (only affects first component)
                let dst0 = self.get_or_alloc(&format!("{}__{}", dst.id(), 0));
                let lhs0 = self.get_var(&format!("{}__{}", lhs.id(), 0));
                let const_idx = self.alloc_const(rhs);
                
                let mut sum = SparseRow::new();
                sum.add_term(lhs0, C::F::one());
                sum.add_term(const_idx, C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    sum,
                    SparseRow::single(dst0),
                );
                
                for i in 1..4 {
                    let dst_i = self.get_or_alloc(&format!("{}__{}", dst.id(), i));
                    let lhs_i = self.get_var(&format!("{}__{}", lhs.id(), i));
                    self.add_eq(dst_i, lhs_i);
                }
            }
            
            DslIr::AddEFFI(dst, lhs, rhs) => {
                // Add felt + extension immediate: dst = felt + ext_imm
                let rhs_base = rhs.as_base_slice();
                let lhs_idx = self.get_var(&lhs.id());
                
                // First component: dst[0] = lhs + rhs[0]
                let dst0 = self.get_or_alloc(&format!("{}__{}", dst.id(), 0));
                let const0 = self.alloc_const(rhs_base[0]);
                let mut sum = SparseRow::new();
                sum.add_term(lhs_idx, C::F::one());
                sum.add_term(const0, C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    sum,
                    SparseRow::single(dst0),
                );
                
                // Other components: dst[i] = rhs[i]
                for i in 1..4 {
                    let dst_i = self.get_or_alloc(&format!("{}__{}", dst.id(), i));
                    let const_i = self.alloc_const(rhs_base[i]);
                    self.add_eq(dst_i, const_i);
                }
            }
            
            DslIr::SubEI(dst, lhs, rhs) => {
                // Subtract extension - extension immediate
                let rhs_base = rhs.as_base_slice();
                for i in 0..4 {
                    let dst_idx = self.get_or_alloc(&format!("{}__{}", dst.id(), i));
                    let lhs_idx = self.get_var(&format!("{}__{}", lhs.id(), i));
                    let const_idx = self.alloc_const(rhs_base[i]);
                    
                    let mut diff = SparseRow::new();
                    diff.add_term(lhs_idx, C::F::one());
                    diff.add_term(const_idx, -C::F::one());
                    self.r1cs.add_constraint(
                        SparseRow::single(0),
                        diff,
                        SparseRow::single(dst_idx),
                    );
                }
            }
            
            DslIr::SubEIN(dst, lhs, rhs) => {
                // Subtract extension immediate - extension: dst = lhs_imm - rhs
                let lhs_base = lhs.as_base_slice();
                for i in 0..4 {
                    let dst_idx = self.get_or_alloc(&format!("{}__{}", dst.id(), i));
                    let rhs_idx = self.get_var(&format!("{}__{}", rhs.id(), i));
                    let const_idx = self.alloc_const(lhs_base[i]);
                    
                    let mut diff = SparseRow::new();
                    diff.add_term(const_idx, C::F::one());
                    diff.add_term(rhs_idx, -C::F::one());
                    self.r1cs.add_constraint(
                        SparseRow::single(0),
                        diff,
                        SparseRow::single(dst_idx),
                    );
                }
            }
            
            DslIr::SubEF(dst, lhs, rhs) => {
                // Subtract extension - felt (only affects first component)
                let dst0 = self.get_or_alloc(&format!("{}__{}", dst.id(), 0));
                let lhs0 = self.get_var(&format!("{}__{}", lhs.id(), 0));
                let rhs_idx = self.get_var(&rhs.id());
                
                let mut diff = SparseRow::new();
                diff.add_term(lhs0, C::F::one());
                diff.add_term(rhs_idx, -C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    diff,
                    SparseRow::single(dst0),
                );
                
                for i in 1..4 {
                    let dst_i = self.get_or_alloc(&format!("{}__{}", dst.id(), i));
                    let lhs_i = self.get_var(&format!("{}__{}", lhs.id(), i));
                    self.add_eq(dst_i, lhs_i);
                }
            }
            
            DslIr::SubEFI(dst, lhs, rhs) => {
                // Subtract extension - field immediate
                let dst0 = self.get_or_alloc(&format!("{}__{}", dst.id(), 0));
                let lhs0 = self.get_var(&format!("{}__{}", lhs.id(), 0));
                let const_idx = self.alloc_const(rhs);
                
                let mut diff = SparseRow::new();
                diff.add_term(lhs0, C::F::one());
                diff.add_term(const_idx, -C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    diff,
                    SparseRow::single(dst0),
                );
                
                for i in 1..4 {
                    let dst_i = self.get_or_alloc(&format!("{}__{}", dst.id(), i));
                    let lhs_i = self.get_var(&format!("{}__{}", lhs.id(), i));
                    self.add_eq(dst_i, lhs_i);
                }
            }
            
            DslIr::MulEI(dst, lhs, rhs) => {
                // Multiply extension * extension immediate
                // This requires full extension multiplication with constant
                let rhs_base = rhs.as_base_slice();
                let nr = C::F::from_canonical_u64(11);
                
                let a: Vec<usize> = (0..4).map(|i| self.get_var(&format!("{}__{}", lhs.id(), i))).collect();
                let c: Vec<usize> = (0..4).map(|i| self.get_or_alloc(&format!("{}__{}", dst.id(), i))).collect();
                
                // c[k] = sum_{i+j=k} a[i]*b[j] + 11 * sum_{i+j=k+4} a[i]*b[j]
                // where b[j] are constants
                for k in 0..4 {
                    let mut terms = SparseRow::new();
                    for i in 0..4 {
                        for j in 0..4 {
                            let idx = i + j;
                            let coeff = if idx == k {
                                rhs_base[j]
                            } else if idx == k + 4 {
                                nr * rhs_base[j]
                            } else {
                                C::F::zero()
                            };
                            if coeff != C::F::zero() {
                                terms.add_term(a[i], coeff);
                            }
                        }
                    }
                    self.r1cs.add_constraint(
                        SparseRow::single(0),
                        terms,
                        SparseRow::single(c[k]),
                    );
                }
            }
            
            DslIr::MulEFI(dst, lhs, rhs) => {
                // Multiply extension * field immediate
                for i in 0..4 {
                    let dst_idx = self.get_or_alloc(&format!("{}__{}", dst.id(), i));
                    let lhs_idx = self.get_var(&format!("{}__{}", lhs.id(), i));
                    
                    // dst[i] = lhs[i] * rhs (constant)
                    self.r1cs.add_constraint(
                        SparseRow::single(0),
                        SparseRow::single_with_coeff(lhs_idx, rhs),
                        SparseRow::single(dst_idx),
                    );
                }
            }
            
            DslIr::DivEI(dst, lhs, rhs) => {
                // Divide extension / extension immediate
                // dst = lhs / rhs, so dst * rhs = lhs
                // Since rhs is constant, we can compute rhs^(-1) and multiply
                // But for R1CS, we just verify: dst * rhs_const = lhs
                let rhs_base = rhs.as_base_slice();
                let nr = C::F::from_canonical_u64(11);
                
                let d: Vec<usize> = (0..4).map(|i| self.get_or_alloc(&format!("{}__{}", dst.id(), i))).collect();
                let l: Vec<usize> = (0..4).map(|i| self.get_var(&format!("{}__{}", lhs.id(), i))).collect();
                
                // Verify dst * rhs_const = lhs using extension multiplication
                // product[k] = sum_{i+j=k} d[i]*rhs[j] + 11 * sum_{i+j=k+4} d[i]*rhs[j]
                for k in 0..4 {
                    let mut terms = SparseRow::new();
                    for i in 0..4 {
                        for j in 0..4 {
                            let idx = i + j;
                            let coeff = if idx == k {
                                rhs_base[j]
                            } else if idx == k + 4 {
                                nr * rhs_base[j]
                            } else {
                                C::F::zero()
                            };
                            if coeff != C::F::zero() {
                                terms.add_term(d[i], coeff);
                            }
                        }
                    }
                    // terms = lhs[k]
                    self.r1cs.add_constraint(
                        SparseRow::single(0),
                        terms,
                        SparseRow::single(l[k]),
                    );
                }
            }
            
            DslIr::DivEIN(dst, lhs, rhs) => {
                // Divide extension immediate / extension: dst = lhs_imm / rhs
                // dst * rhs = lhs_imm
                for i in 0..4 {
                    self.get_or_alloc(&format!("{}__{}", dst.id(), i));
                }
                
                // We need to allocate constant extension and check dst * rhs = const
                let lhs_slice = lhs.as_base_slice();
                let lhs_base: [C::F; 4] = [lhs_slice[0], lhs_slice[1], lhs_slice[2], lhs_slice[3]];
                self.compile_ext_mul_check_const(&dst, &rhs, &lhs_base);
            }
            
            DslIr::DivEF(dst, lhs, rhs) => {
                // Divide extension / felt: dst = lhs / rhs
                // dst * rhs = lhs (component-wise since rhs is base field)
                for i in 0..4 {
                    let dst_idx = self.get_or_alloc(&format!("{}__{}", dst.id(), i));
                    let lhs_idx = self.get_var(&format!("{}__{}", lhs.id(), i));
                    let rhs_idx = self.get_var(&rhs.id());
                    
                    // dst[i] * rhs = lhs[i]
                    self.r1cs.add_constraint(
                        SparseRow::single(dst_idx),
                        SparseRow::single(rhs_idx),
                        SparseRow::single(lhs_idx),
                    );
                }
            }
            
            DslIr::DivEFI(dst, lhs, rhs) => {
                // Divide extension / field immediate
                // dst[i] = lhs[i] / rhs = lhs[i] * rhs^(-1)
                // Verify: dst[i] * rhs = lhs[i]
                for i in 0..4 {
                    let dst_idx = self.get_or_alloc(&format!("{}__{}", dst.id(), i));
                    let lhs_idx = self.get_var(&format!("{}__{}", lhs.id(), i));
                    
                    // dst[i] * rhs_const = lhs[i]
                    self.r1cs.add_constraint(
                        SparseRow::single(0),
                        SparseRow::single_with_coeff(dst_idx, rhs),
                        SparseRow::single(lhs_idx),
                    );
                }
            }
            
            DslIr::DivEFIN(dst, lhs, rhs) => {
                // Divide field immediate / extension: dst = lhs_imm / rhs
                // dst * rhs = (lhs_imm, 0, 0, 0)
                for i in 0..4 {
                    self.get_or_alloc(&format!("{}__{}", dst.id(), i));
                }
                let lhs_base = [lhs, C::F::zero(), C::F::zero(), C::F::zero()];
                self.compile_ext_mul_check_const(&dst, &rhs, &lhs_base);
            }
            
            DslIr::NegE(dst, src) => {
                for i in 0..4 {
                    let dst_idx = self.get_or_alloc(&format!("{}__{}", dst.id(), i));
                    let src_idx = self.get_var(&format!("{}__{}", src.id(), i));
                    
                    let mut neg = SparseRow::new();
                    neg.add_term(src_idx, -C::F::one());
                    self.r1cs.add_constraint(
                        SparseRow::single(0),
                        neg,
                        SparseRow::single(dst_idx),
                    );
                }
            }
            
            DslIr::InvE(dst, src) => {
                // Extension inverse: hint + multiplication check
                // Hint provides dst, we verify dst * src = 1
                for i in 0..4 {
                    self.get_or_alloc(&format!("{}__{}", dst.id(), i));
                }
                
                // dst * src should equal (1, 0, 0, 0)
                self.compile_ext_mul_and_check_one(&dst, &src);
            }
            
            DslIr::DivE(dst, lhs, rhs) => {
                // dst = lhs / rhs = lhs * rhs^(-1)
                // Hint dst, verify dst * rhs = lhs
                for i in 0..4 {
                    self.get_or_alloc(&format!("{}__{}", dst.id(), i));
                }
                self.compile_ext_mul_check(&dst, &rhs, &lhs);
            }
            
            DslIr::AssertEqE(lhs, rhs) => {
                for i in 0..4 {
                    let lhs_idx = self.get_var(&format!("{}__{}", lhs.id(), i));
                    let rhs_idx = self.get_var(&format!("{}__{}", rhs.id(), i));
                    self.add_eq(lhs_idx, rhs_idx);
                }
            }
            
            DslIr::AssertEqEI(lhs, rhs) => {
                let rhs_base = rhs.as_base_slice();
                for i in 0..4 {
                    let lhs_idx = self.get_var(&format!("{}__{}", lhs.id(), i));
                    let const_idx = self.alloc_const(rhs_base[i]);
                    self.add_eq(lhs_idx, const_idx);
                }
            }
            
            DslIr::CircuitSelectE(cond, a, b, out) => {
                let cond_idx = self.get_var(&cond.id());
                // Add boolean constraint on cond
                self.add_boolean(cond_idx);
                
                for i in 0..4 {
                    let out_idx = self.get_or_alloc(&format!("{}__{}", out.id(), i));
                    let a_idx = self.get_var(&format!("{}__{}", a.id(), i));
                    let b_idx = self.get_var(&format!("{}__{}", b.id(), i));
                    
                    // out = cond * (a - b) + b
                    let mut a_minus_b = SparseRow::new();
                    a_minus_b.add_term(a_idx, C::F::one());
                    a_minus_b.add_term(b_idx, -C::F::one());
                    
                    let mut out_minus_b = SparseRow::new();
                    out_minus_b.add_term(out_idx, C::F::one());
                    out_minus_b.add_term(b_idx, -C::F::one());
                    
                    self.r1cs.add_constraint(
                        SparseRow::single(cond_idx),
                        a_minus_b,
                        out_minus_b,
                    );
                }
            }
            
            DslIr::CircuitExt2Felt(felts, ext) => {
                // Extract 4 felt components from extension
                for i in 0..4 {
                    let felt_idx = self.get_or_alloc(&felts[i].id());
                    let ext_idx = self.get_var(&format!("{}__{}", ext.id(), i));
                    self.add_eq(felt_idx, ext_idx);
                }
            }
            
            DslIr::CircuitFelts2Ext(felts, ext) => {
                // Pack 4 felts into extension
                for i in 0..4 {
                    let ext_idx = self.get_or_alloc(&format!("{}__{}", ext.id(), i));
                    let felt_idx = self.get_var(&felts[i].id());
                    self.add_eq(ext_idx, felt_idx);
                }
            }
            
            DslIr::CircuitFelt2Var(felt, var) => {
                let felt_idx = self.get_var(&felt.id());
                let var_idx = self.get_or_alloc(&var.id());
                self.add_eq(var_idx, felt_idx);
            }
            
            DslIr::ReduceE(_ext) => {
                // Reduce extension field element (no-op in R1CS, just tracks the variable)
                // The reduction is implicit in how we handle values
            }

            // === Parallel blocks ===
            DslIr::Parallel(blocks) => {
                for block in blocks {
                    for op in block.ops {
                        self.compile_one(op);
                    }
                }
            }

            // === Ignored operations (debug/instrumentation) ===
            DslIr::CycleTracker(_) 
            | DslIr::CycleTrackerV2Enter(_) 
            | DslIr::CycleTrackerV2Exit
            | DslIr::DebugBacktrace(_)
            | DslIr::CircuitV2CommitPublicValues(_)
            | DslIr::PrintV(_)
            | DslIr::PrintF(_)
            | DslIr::PrintE(_)
            | DslIr::Halt
            | DslIr::Error() => {
                // These are debug/instrumentation/control, no R1CS needed
            }
            
            // === CircuitV2HintAddCurve: Elliptic curve point addition hint ===
            // The sum is computed outside the circuit and witnessed.
            // SepticCurve has x, y fields each with 7 Felt components (SepticExtension).
            DslIr::CircuitV2HintAddCurve(boxed) => {
                let (sum, _p1, _p2) = boxed.as_ref();
                // Allocate all 14 felts for sum (7 for x, 7 for y)
                for felt in sum.x.0.iter().chain(sum.y.0.iter()) {
                    let _ = self.get_or_alloc(&felt.id());
                }
            }
            
            // === Catch-all for remaining unhandled variants ===
            // These are variants not used by the shrink verifier circuit.
            DslIr::SubVI(..) => panic!("Unhandled DslIr: SubVI"),
            DslIr::SubVIN(..) => panic!("Unhandled DslIr: SubVIN"),
            DslIr::For(..) => panic!("Unhandled DslIr: For (control flow not supported in R1CS)"),
            DslIr::IfEq(..) => panic!("Unhandled DslIr: IfEq"),
            DslIr::IfNe(..) => panic!("Unhandled DslIr: IfNe"),
            DslIr::IfEqI(..) => panic!("Unhandled DslIr: IfEqI"),
            DslIr::IfNeI(..) => panic!("Unhandled DslIr: IfNeI"),
            DslIr::Break => panic!("Unhandled DslIr: Break"),
            DslIr::AssertNeE(..) => panic!("Unhandled DslIr: AssertNeE"),
            DslIr::AssertNeEI(..) => panic!("Unhandled DslIr: AssertNeEI"),
            DslIr::Alloc(..) => panic!("Unhandled DslIr: Alloc (memory ops not supported)"),
            DslIr::LoadV(..) => panic!("Unhandled DslIr: LoadV"),
            DslIr::LoadF(..) => panic!("Unhandled DslIr: LoadF"),
            DslIr::LoadE(..) => panic!("Unhandled DslIr: LoadE"),
            DslIr::StoreV(..) => panic!("Unhandled DslIr: StoreV"),
            DslIr::StoreF(..) => panic!("Unhandled DslIr: StoreF"),
            DslIr::StoreE(..) => panic!("Unhandled DslIr: StoreE"),
            DslIr::Poseidon2PermuteBabyBear(..) => panic!("Unhandled DslIr: Poseidon2PermuteBabyBear (use CircuitV2 variant)"),
            DslIr::Poseidon2CompressBabyBear(..) => panic!("Unhandled DslIr: Poseidon2CompressBabyBear"),
            DslIr::Poseidon2AbsorbBabyBear(..) => panic!("Unhandled DslIr: Poseidon2AbsorbBabyBear"),
            DslIr::Poseidon2FinalizeBabyBear(..) => panic!("Unhandled DslIr: Poseidon2FinalizeBabyBear"),
            DslIr::HintBitsU(..) => panic!("Unhandled DslIr: HintBitsU"),
            DslIr::HintBitsV(..) => panic!("Unhandled DslIr: HintBitsV"),
            DslIr::HintBitsF(..) => panic!("Unhandled DslIr: HintBitsF"),
            DslIr::HintExt2Felt(..) => panic!("Unhandled DslIr: HintExt2Felt"),
            DslIr::HintLen(..) => panic!("Unhandled DslIr: HintLen"),
            DslIr::HintVars(..) => panic!("Unhandled DslIr: HintVars"),
            DslIr::HintFelts(..) => panic!("Unhandled DslIr: HintFelts"),
            DslIr::HintExts(..) => panic!("Unhandled DslIr: HintExts"),
            DslIr::Commit(..) => panic!("Unhandled DslIr: Commit"),
            DslIr::RegisterPublicValue(..) => panic!("Unhandled DslIr: RegisterPublicValue"),
            DslIr::FriFold(..) => panic!("Unhandled DslIr: FriFold (use CircuitV2FriFold)"),
            DslIr::LessThan(..) => panic!("Unhandled DslIr: LessThan"),
            DslIr::ExpReverseBitsLen(..) => panic!("Unhandled DslIr: ExpReverseBitsLen (use CircuitV2ExpReverseBits)")
        }
    }

    /// Compile extension field multiplication
    fn compile_ext_mul(&mut self, dst: &Ext<C::F, C::EF>, lhs: &Ext<C::F, C::EF>, rhs: &Ext<C::F, C::EF>) {
        // F_p[u]/(u^4 - 11)
        // Result[k] = sum_{i+j=k} a[i]*b[j] + 11 * sum_{i+j=k+4} a[i]*b[j]
        let nr = C::F::from_canonical_u64(11);
        
        let a: Vec<usize> = (0..4).map(|i| self.get_var(&format!("{}__{}", lhs.id(), i))).collect();
        let b: Vec<usize> = (0..4).map(|i| self.get_var(&format!("{}__{}", rhs.id(), i))).collect();
        let c: Vec<usize> = (0..4).map(|i| self.get_or_alloc(&format!("{}__{}", dst.id(), i))).collect();
        
        // We need intermediate products
        // a[i] * b[j] for all i, j in 0..4
        let mut products = [[0usize; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                let prod_idx = self.alloc_var();
                products[i][j] = prod_idx;
                self.add_mul(prod_idx, a[i], b[j]);
            }
        }
        
        // Now compute each output component
        for k in 0..4 {
            // c[k] = sum of terms
            let mut terms = SparseRow::new();
            for i in 0..4 {
                for j in 0..4 {
                    let idx = i + j;
                    if idx == k {
                        terms.add_term(products[i][j], C::F::one());
                    } else if idx == k + 4 {
                        terms.add_term(products[i][j], nr);
                    }
                }
            }
            
            // c[k] = terms (linear combination)
            self.r1cs.add_constraint(
                SparseRow::single(0),
                terms,
                SparseRow::single(c[k]),
            );
        }
    }

    /// Compile extension multiplication and check result equals (1, 0, 0, 0)
    fn compile_ext_mul_and_check_one(&mut self, dst: &Ext<C::F, C::EF>, src: &Ext<C::F, C::EF>) {
        // dst * src = 1
        // Allocate result components and check
        let nr = C::F::from_canonical_u64(11);
        
        let a: Vec<usize> = (0..4).map(|i| self.get_var(&format!("{}__{}", dst.id(), i))).collect();
        let b: Vec<usize> = (0..4).map(|i| self.get_var(&format!("{}__{}", src.id(), i))).collect();
        
        // Products
        let mut products = [[0usize; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                let prod_idx = self.alloc_var();
                products[i][j] = prod_idx;
                self.add_mul(prod_idx, a[i], b[j]);
            }
        }
        
        // Check each component
        for k in 0..4 {
            let mut terms = SparseRow::new();
            for i in 0..4 {
                for j in 0..4 {
                    let idx = i + j;
                    if idx == k {
                        terms.add_term(products[i][j], C::F::one());
                    } else if idx == k + 4 {
                        terms.add_term(products[i][j], nr);
                    }
                }
            }
            
            // c[0] should be 1, c[1..4] should be 0
            let expected = if k == 0 { C::F::one() } else { C::F::zero() };
            
            // terms = expected
            self.r1cs.add_constraint(
                SparseRow::single(0),
                terms,
                SparseRow::constant(expected),
            );
        }
    }

    /// Compile extension multiplication check: a * b = c
    fn compile_ext_mul_check(&mut self, a: &Ext<C::F, C::EF>, b: &Ext<C::F, C::EF>, c: &Ext<C::F, C::EF>) {
        let nr = C::F::from_canonical_u64(11);
        
        let a_vars: Vec<usize> = (0..4).map(|i| self.get_var(&format!("{}__{}", a.id(), i))).collect();
        let b_vars: Vec<usize> = (0..4).map(|i| self.get_var(&format!("{}__{}", b.id(), i))).collect();
        let c_vars: Vec<usize> = (0..4).map(|i| self.get_var(&format!("{}__{}", c.id(), i))).collect();
        
        // Products
        let mut products = [[0usize; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                let prod_idx = self.alloc_var();
                products[i][j] = prod_idx;
                self.add_mul(prod_idx, a_vars[i], b_vars[j]);
            }
        }
        
        // Check each component equals c
        for k in 0..4 {
            let mut terms = SparseRow::new();
            for i in 0..4 {
                for j in 0..4 {
                    let idx = i + j;
                    if idx == k {
                        terms.add_term(products[i][j], C::F::one());
                    } else if idx == k + 4 {
                        terms.add_term(products[i][j], nr);
                    }
                }
            }
            
            // terms = c[k]
            self.r1cs.add_constraint(
                SparseRow::single(0),
                terms,
                SparseRow::single(c_vars[k]),
            );
        }
    }

    /// Compile extension multiplication check: a * b = c_const (where c is a constant)
    fn compile_ext_mul_check_const(&mut self, a: &Ext<C::F, C::EF>, b: &Ext<C::F, C::EF>, c_const: &[C::F; 4]) {
        let nr = C::F::from_canonical_u64(11);
        
        let a_vars: Vec<usize> = (0..4).map(|i| self.get_var(&format!("{}__{}", a.id(), i))).collect();
        let b_vars: Vec<usize> = (0..4).map(|i| self.get_var(&format!("{}__{}", b.id(), i))).collect();
        
        // Products
        let mut products = [[0usize; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                let prod_idx = self.alloc_var();
                products[i][j] = prod_idx;
                self.add_mul(prod_idx, a_vars[i], b_vars[j]);
            }
        }
        
        // Check each component equals c_const
        for k in 0..4 {
            let mut terms = SparseRow::new();
            for i in 0..4 {
                for j in 0..4 {
                    let idx = i + j;
                    if idx == k {
                        terms.add_term(products[i][j], C::F::one());
                    } else if idx == k + 4 {
                        terms.add_term(products[i][j], nr);
                    }
                }
            }
            
            // terms = c_const[k]
            self.r1cs.add_constraint(
                SparseRow::single(0),
                terms,
                SparseRow::constant(c_const[k]),
            );
        }
    }

    /// Compile extension multiplication from raw indices: c = a * b
    fn compile_ext_mul_from_indices(&mut self, c: &[usize], a: &[usize], b: &[usize]) {
        let nr = C::F::from_canonical_u64(11);
        
        // Products: a[i] * b[j]
        let mut products = [[0usize; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                let prod_idx = self.alloc_var();
                products[i][j] = prod_idx;
                self.add_mul(prod_idx, a[i], b[j]);
            }
        }
        
        // Compute each output component
        for k in 0..4 {
            let mut terms = SparseRow::new();
            for i in 0..4 {
                for j in 0..4 {
                    let idx = i + j;
                    if idx == k {
                        terms.add_term(products[i][j], C::F::one());
                    } else if idx == k + 4 {
                        terms.add_term(products[i][j], nr);
                    }
                }
            }
            self.r1cs.add_constraint(
                SparseRow::single(0),
                terms,
                SparseRow::single(c[k]),
            );
        }
    }

    /// Compile extension multiplication check from raw indices: a * b = c
    fn compile_ext_mul_check_from_indices(&mut self, a: &[usize], b: &[usize], c: &[usize]) {
        let nr = C::F::from_canonical_u64(11);
        
        // Products: a[i] * b[j]
        let mut products = [[0usize; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                let prod_idx = self.alloc_var();
                products[i][j] = prod_idx;
                self.add_mul(prod_idx, a[i], b[j]);
            }
        }
        
        // Check each component equals c[k]
        for k in 0..4 {
            let mut terms = SparseRow::new();
            for i in 0..4 {
                for j in 0..4 {
                    let idx = i + j;
                    if idx == k {
                        terms.add_term(products[i][j], C::F::one());
                    } else if idx == k + 4 {
                        terms.add_term(products[i][j], nr);
                    }
                }
            }
            self.r1cs.add_constraint(
                SparseRow::single(0),
                terms,
                SparseRow::single(c[k]),
            );
        }
    }

    /// Compile all operations and return the R1CS
    pub fn compile(operations: Vec<DslIr<C>>) -> R1CS<C::F> {
        let mut compiler = Self::new();
        for op in operations {
            compiler.compile_one(op);
        }
        compiler.r1cs.num_public = compiler.public_inputs.len();
        compiler.r1cs
    }
}

impl<C: Config> Default for R1CSCompiler<C>
where
    C::F: PrimeField64,
{
    fn default() -> Self {
        Self::new()
    }
}
