//! Poseidon2 R1CS expansion for BabyBear.
//!
//! This module expands Poseidon2 permutation into explicit R1CS constraints.
//! The S-box for BabyBear is x^7, which requires 4 multiplication constraints.
//!
//! SECURITY CRITICAL: This must be semantically equivalent to SP1's native Poseidon2.
//! Round constants sourced from: sp1/crates/recursion/gnark-ffi/go/sp1/poseidon2/constants.go

use p3_field::{PrimeField32, PrimeField64};
use super::types::{R1CS, SparseRow};
use p3_baby_bear::{MONTY_INVERSE, POSEIDON2_INTERNAL_MATRIX_DIAG_16_BABYBEAR_MONTY};
use sp1_primitives::RC_16_30_U32;

/// Poseidon2 parameters for BabyBear
pub const WIDTH: usize = 16;
pub const NUM_EXTERNAL_ROUNDS: usize = 8;
pub const NUM_INTERNAL_ROUNDS: usize = 13;
pub const TOTAL_ROUNDS: usize = NUM_EXTERNAL_ROUNDS + NUM_INTERNAL_ROUNDS; // 21

/// Get round constants as field elements
/// Note: Values in `RC_16_30_U32` may exceed the field modulus, so we use `from_wrapped_u32`.
pub fn get_round_constants<F: PrimeField64>() -> Vec<[F; WIDTH]> {
    RC_16_30_U32.iter()
        .map(|row| {
            let mut result = [F::zero(); WIDTH];
            for (i, &v) in row.iter().enumerate() {
                result[i] = F::from_wrapped_u32(v);
            }
            result
        })
        .collect()
}

/// Internal diagonal matrix constants (matInternalDiagM1)
pub fn get_internal_diag<F: PrimeField64>() -> [F; WIDTH] {
    // Keep exactly consistent with `sp1_recursion_core::chips::poseidon2_skinny::internal_linear_layer`.
    POSEIDON2_INTERNAL_MATRIX_DIAG_16_BABYBEAR_MONTY
        .iter()
        .map(|x| F::from_wrapped_u32(x.as_canonical_u32()))
        .collect::<Vec<_>>()
        .try_into()
        .expect("internal diag has WIDTH elements")
}

/// Monty inverse constant
pub fn get_monty_inverse<F: PrimeField64>() -> F {
    // Keep exactly consistent with `sp1_recursion_core::chips::poseidon2_skinny::internal_linear_layer`.
    F::from_wrapped_u32(MONTY_INVERSE.as_canonical_u32())
}

/// R1CS helper for Poseidon2 expansion
pub struct Poseidon2R1CS<F: PrimeField64> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: PrimeField64> Poseidon2R1CS<F> {
    /// Expand a BabyBear Poseidon2 permutation into R1CS constraints.
    ///
    /// Returns the output state variable indices. The caller is responsible
    /// for binding these to the declared output variables.
    ///
    /// # Arguments
    /// * `r1cs` - The R1CS being constructed
    /// * `next_var` - Next available variable index (updated by this function)
    /// * `input_state` - The 16 input state variable indices
    ///
    /// # Returns
    /// The 16 output state variable indices
    pub fn expand_permute_babybear(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        input_state: &[usize],
    ) -> [usize; WIDTH] {
        assert_eq!(input_state.len(), WIDTH);
        
        // Working state (we'll track current indices for each position)
        let mut current_state: [usize; WIDTH] = input_state.try_into().unwrap();
        
        let rc = get_round_constants::<F>();
        let internal_diag = get_internal_diag::<F>();
        let monty_inv = get_monty_inverse::<F>();
        
        // Initial linear layer
        Self::external_linear_layer(r1cs, next_var, &mut current_state);
        
        // First half of external rounds (4 rounds)
        let rounds_f_beginning = NUM_EXTERNAL_ROUNDS / 2;
        for r in 0..rounds_f_beginning {
            Self::add_round_constants(r1cs, next_var, &mut current_state, &rc[r]);
            Self::sbox_layer(r1cs, next_var, &mut current_state);
            Self::external_linear_layer(r1cs, next_var, &mut current_state);
        }
        
        // Internal rounds (13 rounds)
        let p_end = rounds_f_beginning + NUM_INTERNAL_ROUNDS;
        for r in rounds_f_beginning..p_end {
            // Only add RC to first element
            current_state[0] = Self::add_const(r1cs, next_var, current_state[0], rc[r][0]);
            // S-box only on first element
            current_state[0] = Self::sbox_single(r1cs, next_var, current_state[0]);
            // Diffusion permutation
            Self::diffusion_permute(r1cs, next_var, &mut current_state, &internal_diag, monty_inv);
        }
        
        // Second half of external rounds (4 rounds)
        let total_rounds = NUM_EXTERNAL_ROUNDS + NUM_INTERNAL_ROUNDS;
        for r in p_end..total_rounds {
            Self::add_round_constants(r1cs, next_var, &mut current_state, &rc[r]);
            Self::sbox_layer(r1cs, next_var, &mut current_state);
            Self::external_linear_layer(r1cs, next_var, &mut current_state);
        }
        
        // Return the computed output state indices
        current_state
    }

    /// Expand a BabyBear Poseidon2 permutation into R1CS constraints **and** compute witness
    /// values for all intermediate variables allocated during the expansion.
    ///
    /// The caller must provide a witness vector where:
    /// - `witness[0] == 1` (constant one),
    /// - `witness[input_state[i]]` is already populated for all inputs.
    ///
    /// This function will `resize` the witness vector as needed and will assign values to every
    /// newly allocated variable index, exactly matching the allocation order used by
    /// `expand_permute_babybear`.
    pub fn expand_permute_babybear_with_witness(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        input_state: &[usize],
        witness: &mut Vec<F>,
    ) -> [usize; WIDTH] {
        assert_eq!(input_state.len(), WIDTH);

        // Ensure witness is large enough for current indices.
        let need = (*next_var).max(input_state.iter().copied().max().unwrap_or(0) + 1);
        if witness.len() < need {
            witness.resize(need, F::zero());
        }

        // Working state (we'll track current indices for each position)
        let mut current_state: [usize; WIDTH] = input_state.try_into().unwrap();

        let rc = get_round_constants::<F>();
        let internal_diag = get_internal_diag::<F>();
        let monty_inv = get_monty_inverse::<F>();

        // Initial linear layer
        Self::external_linear_layer_w(r1cs, next_var, &mut current_state, witness);

        // First half of external rounds (4 rounds)
        let rounds_f_beginning = NUM_EXTERNAL_ROUNDS / 2;
        for r in 0..rounds_f_beginning {
            Self::add_round_constants_w(r1cs, next_var, &mut current_state, &rc[r], witness);
            Self::sbox_layer_w(r1cs, next_var, &mut current_state, witness);
            Self::external_linear_layer_w(r1cs, next_var, &mut current_state, witness);
        }

        // Internal rounds (13 rounds)
        let p_end = rounds_f_beginning + NUM_INTERNAL_ROUNDS;
        for r in rounds_f_beginning..p_end {
            // Only add RC to first element
            current_state[0] = Self::add_const_w(r1cs, next_var, current_state[0], rc[r][0], witness);
            // S-box only on first element
            current_state[0] = Self::sbox_single_w(r1cs, next_var, current_state[0], witness);
            // Diffusion permutation
            Self::diffusion_permute_w(
                r1cs,
                next_var,
                &mut current_state,
                &internal_diag,
                monty_inv,
                witness,
            );
        }

        // Second half of external rounds (4 rounds)
        let total_rounds = NUM_EXTERNAL_ROUNDS + NUM_INTERNAL_ROUNDS;
        for r in p_end..total_rounds {
            Self::add_round_constants_w(r1cs, next_var, &mut current_state, &rc[r], witness);
            Self::sbox_layer_w(r1cs, next_var, &mut current_state, witness);
            Self::external_linear_layer_w(r1cs, next_var, &mut current_state, witness);
        }

        current_state
    }
    
    /// Allocate a new variable
    fn alloc(next_var: &mut usize) -> usize {
        let idx = *next_var;
        *next_var += 1;
        idx
    }

    fn alloc_w(next_var: &mut usize, r1cs: &mut R1CS<F>, witness: &mut Vec<F>) -> usize {
        let idx = Self::alloc(next_var);
        r1cs.num_vars = *next_var;
        if witness.len() < *next_var {
            witness.resize(*next_var, F::zero());
        }
        idx
    }
    
    /// Add a constant to a variable: result = var + const
    fn add_const(r1cs: &mut R1CS<F>, next_var: &mut usize, var: usize, constant: F) -> usize {
        if constant.is_zero() {
            return var;
        }
        let result = Self::alloc(next_var);
        r1cs.num_vars = *next_var;
        
        // result = var + constant
        // (1) * (var + constant) = result
        let mut sum = SparseRow::new();
        sum.add_term(var, F::one());
        sum.add_term(0, constant); // constant uses index 0 (which holds 1)
        r1cs.add_constraint(
            SparseRow::single(0),
            sum,
            SparseRow::single(result),
        );
        result
    }

    fn add_const_w(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        var: usize,
        constant: F,
        witness: &mut Vec<F>,
    ) -> usize {
        if constant.is_zero() {
            return var;
        }
        let result = Self::alloc_w(next_var, r1cs, witness);
        witness[result] = witness[var] + constant;

        // result = var + constant
        // (1) * (var + constant) = result
        let mut sum = SparseRow::new();
        sum.add_term(var, F::one());
        sum.add_term(0, constant); // constant uses index 0 (which holds 1)
        r1cs.add_constraint(
            SparseRow::single(0),
            sum,
            SparseRow::single(result),
        );
        result
    }
    
    /// Multiply two variables: result = a * b
    fn mul(r1cs: &mut R1CS<F>, next_var: &mut usize, a: usize, b: usize) -> usize {
        let result = Self::alloc(next_var);
        r1cs.num_vars = *next_var;
        
        r1cs.add_constraint(
            SparseRow::single(a),
            SparseRow::single(b),
            SparseRow::single(result),
        );
        result
    }

    fn mul_w(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        a: usize,
        b: usize,
        witness: &mut Vec<F>,
    ) -> usize {
        let result = Self::alloc_w(next_var, r1cs, witness);
        witness[result] = witness[a] * witness[b];
        r1cs.add_constraint(
            SparseRow::single(a),
            SparseRow::single(b),
            SparseRow::single(result),
        );
        result
    }
    
    /// Multiply variable by constant: result = var * const
    fn mul_const(r1cs: &mut R1CS<F>, next_var: &mut usize, var: usize, constant: F) -> usize {
        if constant == F::one() {
            return var;
        }
        let result = Self::alloc(next_var);
        r1cs.num_vars = *next_var;
        
        // result = var * constant
        // (1) * (var * constant) = result
        r1cs.add_constraint(
            SparseRow::single(0),
            SparseRow::single_with_coeff(var, constant),
            SparseRow::single(result),
        );
        result
    }

    fn mul_const_w(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        var: usize,
        constant: F,
        witness: &mut Vec<F>,
    ) -> usize {
        if constant == F::one() {
            return var;
        }
        let result = Self::alloc_w(next_var, r1cs, witness);
        witness[result] = witness[var] * constant;
        r1cs.add_constraint(
            SparseRow::single(0),
            SparseRow::single_with_coeff(var, constant),
            SparseRow::single(result),
        );
        result
    }
    
    /// Add two variables: result = a + b
    fn add(r1cs: &mut R1CS<F>, next_var: &mut usize, a: usize, b: usize) -> usize {
        let result = Self::alloc(next_var);
        r1cs.num_vars = *next_var;
        
        let mut sum = SparseRow::new();
        sum.add_term(a, F::one());
        sum.add_term(b, F::one());
        r1cs.add_constraint(
            SparseRow::single(0),
            sum,
            SparseRow::single(result),
        );
        result
    }

    fn add_w(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        a: usize,
        b: usize,
        witness: &mut Vec<F>,
    ) -> usize {
        let result = Self::alloc_w(next_var, r1cs, witness);
        witness[result] = witness[a] + witness[b];
        let mut sum = SparseRow::new();
        sum.add_term(a, F::one());
        sum.add_term(b, F::one());
        r1cs.add_constraint(
            SparseRow::single(0),
            sum,
            SparseRow::single(result),
        );
        result
    }
    
    /// S-box: x^7 using 4 multiplications
    /// x² = x * x
    /// x⁴ = x² * x²
    /// x⁶ = x⁴ * x²
    /// x⁷ = x⁶ * x
    pub fn sbox_single(r1cs: &mut R1CS<F>, next_var: &mut usize, x: usize) -> usize {
        let x2 = Self::mul(r1cs, next_var, x, x);
        let x4 = Self::mul(r1cs, next_var, x2, x2);
        let x6 = Self::mul(r1cs, next_var, x4, x2);
        let x7 = Self::mul(r1cs, next_var, x6, x);
        x7
    }

    fn sbox_single_w(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        x: usize,
        witness: &mut Vec<F>,
    ) -> usize {
        let x2 = Self::mul_w(r1cs, next_var, x, x, witness);
        let x4 = Self::mul_w(r1cs, next_var, x2, x2, witness);
        let x6 = Self::mul_w(r1cs, next_var, x4, x2, witness);
        let x7 = Self::mul_w(r1cs, next_var, x6, x, witness);
        x7
    }
    
    /// Apply S-box to all state elements
    fn sbox_layer(r1cs: &mut R1CS<F>, next_var: &mut usize, state: &mut [usize; WIDTH]) {
        for i in 0..WIDTH {
            state[i] = Self::sbox_single(r1cs, next_var, state[i]);
        }
    }

    fn sbox_layer_w(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        state: &mut [usize; WIDTH],
        witness: &mut Vec<F>,
    ) {
        for i in 0..WIDTH {
            state[i] = Self::sbox_single_w(r1cs, next_var, state[i], witness);
        }
    }
    
    /// Add round constants to state
    fn add_round_constants(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        state: &mut [usize; WIDTH],
        rc: &[F; WIDTH],
    ) {
        for i in 0..WIDTH {
            state[i] = Self::add_const(r1cs, next_var, state[i], rc[i]);
        }
    }

    fn add_round_constants_w(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        state: &mut [usize; WIDTH],
        rc: &[F; WIDTH],
        witness: &mut Vec<F>,
    ) {
        for i in 0..WIDTH {
            state[i] = Self::add_const_w(r1cs, next_var, state[i], rc[i], witness);
        }
    }
    
    /// MDS light permutation for 4x4 block
    fn mds_light_4x4(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        state: &mut [usize],
    ) {
        assert_eq!(state.len(), 4);
        
        // t01 = state[0] + state[1]
        let t01 = Self::add(r1cs, next_var, state[0], state[1]);
        // t23 = state[2] + state[3]
        let t23 = Self::add(r1cs, next_var, state[2], state[3]);
        // t0123 = t01 + t23
        let t0123 = Self::add(r1cs, next_var, t01, t23);
        // t01123 = t0123 + state[1]
        let t01123 = Self::add(r1cs, next_var, t0123, state[1]);
        // t01233 = t0123 + state[3]
        let t01233 = Self::add(r1cs, next_var, t0123, state[3]);
        
        // state[3] = t01233 + 2*state[0]
        let two_s0 = Self::mul_const(r1cs, next_var, state[0], F::from_canonical_u64(2));
        let new_s3 = Self::add(r1cs, next_var, t01233, two_s0);
        
        // state[1] = t01123 + 2*state[2]
        let two_s2 = Self::mul_const(r1cs, next_var, state[2], F::from_canonical_u64(2));
        let new_s1 = Self::add(r1cs, next_var, t01123, two_s2);
        
        // state[0] = t01123 + t01
        let new_s0 = Self::add(r1cs, next_var, t01123, t01);
        
        // state[2] = t01233 + t23
        let new_s2 = Self::add(r1cs, next_var, t01233, t23);
        
        state[0] = new_s0;
        state[1] = new_s1;
        state[2] = new_s2;
        state[3] = new_s3;
    }

    fn mds_light_4x4_w(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        state: &mut [usize],
        witness: &mut Vec<F>,
    ) {
        assert_eq!(state.len(), 4);

        let t01 = Self::add_w(r1cs, next_var, state[0], state[1], witness);
        let t23 = Self::add_w(r1cs, next_var, state[2], state[3], witness);
        let t0123 = Self::add_w(r1cs, next_var, t01, t23, witness);
        let t01123 = Self::add_w(r1cs, next_var, t0123, state[1], witness);
        let t01233 = Self::add_w(r1cs, next_var, t0123, state[3], witness);

        let two_s0 = Self::mul_const_w(r1cs, next_var, state[0], F::from_canonical_u64(2), witness);
        let new_s3 = Self::add_w(r1cs, next_var, t01233, two_s0, witness);

        let two_s2 = Self::mul_const_w(r1cs, next_var, state[2], F::from_canonical_u64(2), witness);
        let new_s1 = Self::add_w(r1cs, next_var, t01123, two_s2, witness);

        let new_s0 = Self::add_w(r1cs, next_var, t01123, t01, witness);
        let new_s2 = Self::add_w(r1cs, next_var, t01233, t23, witness);

        state[0] = new_s0;
        state[1] = new_s1;
        state[2] = new_s2;
        state[3] = new_s3;
    }
    
    /// External linear layer
    fn external_linear_layer(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        state: &mut [usize; WIDTH],
    ) {
        // Apply 4x4 MDS to each block of 4
        for i in (0..WIDTH).step_by(4) {
            let mut block = [state[i], state[i+1], state[i+2], state[i+3]];
            Self::mds_light_4x4(r1cs, next_var, &mut block);
            state[i] = block[0];
            state[i+1] = block[1];
            state[i+2] = block[2];
            state[i+3] = block[3];
        }
        
        // Compute sums
        let mut sums = [state[0], state[1], state[2], state[3]];
        for i in (4..WIDTH).step_by(4) {
            sums[0] = Self::add(r1cs, next_var, sums[0], state[i]);
            sums[1] = Self::add(r1cs, next_var, sums[1], state[i+1]);
            sums[2] = Self::add(r1cs, next_var, sums[2], state[i+2]);
            sums[3] = Self::add(r1cs, next_var, sums[3], state[i+3]);
        }
        
        // Add sums to each element
        for i in 0..WIDTH {
            state[i] = Self::add(r1cs, next_var, state[i], sums[i % 4]);
        }
    }

    fn external_linear_layer_w(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        state: &mut [usize; WIDTH],
        witness: &mut Vec<F>,
    ) {
        for i in (0..WIDTH).step_by(4) {
            let mut block = [state[i], state[i + 1], state[i + 2], state[i + 3]];
            Self::mds_light_4x4_w(r1cs, next_var, &mut block, witness);
            state[i] = block[0];
            state[i + 1] = block[1];
            state[i + 2] = block[2];
            state[i + 3] = block[3];
        }

        let mut sums = [state[0], state[1], state[2], state[3]];
        for i in (4..WIDTH).step_by(4) {
            sums[0] = Self::add_w(r1cs, next_var, sums[0], state[i], witness);
            sums[1] = Self::add_w(r1cs, next_var, sums[1], state[i + 1], witness);
            sums[2] = Self::add_w(r1cs, next_var, sums[2], state[i + 2], witness);
            sums[3] = Self::add_w(r1cs, next_var, sums[3], state[i + 3], witness);
        }

        for i in 0..WIDTH {
            state[i] = Self::add_w(r1cs, next_var, state[i], sums[i % 4], witness);
        }
    }
    
    /// Internal matrix multiplication
    fn matmul_internal(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        state: &mut [usize; WIDTH],
        diag: &[F; WIDTH],
    ) {
        // sum = sum of all state elements
        let mut sum = state[0];
        for i in 1..WIDTH {
            sum = Self::add(r1cs, next_var, sum, state[i]);
        }
        
        // state[i] = state[i] * diag[i] + sum
        for i in 0..WIDTH {
            let scaled = Self::mul_const(r1cs, next_var, state[i], diag[i]);
            state[i] = Self::add(r1cs, next_var, scaled, sum);
        }
    }

    fn matmul_internal_w(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        state: &mut [usize; WIDTH],
        diag: &[F; WIDTH],
        witness: &mut Vec<F>,
    ) {
        let mut sum = state[0];
        for i in 1..WIDTH {
            sum = Self::add_w(r1cs, next_var, sum, state[i], witness);
        }
        for i in 0..WIDTH {
            let scaled = Self::mul_const_w(r1cs, next_var, state[i], diag[i], witness);
            state[i] = Self::add_w(r1cs, next_var, scaled, sum, witness);
        }
    }
    
    /// Diffusion permutation (internal rounds)
    fn diffusion_permute(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        state: &mut [usize; WIDTH],
        internal_diag: &[F; WIDTH],
        monty_inv: F,
    ) {
        Self::matmul_internal(r1cs, next_var, state, internal_diag);
        
        // Multiply each element by monty_inv
        for i in 0..WIDTH {
            state[i] = Self::mul_const(r1cs, next_var, state[i], monty_inv);
        }
    }

    fn diffusion_permute_w(
        r1cs: &mut R1CS<F>,
        next_var: &mut usize,
        state: &mut [usize; WIDTH],
        internal_diag: &[F; WIDTH],
        monty_inv: F,
        witness: &mut Vec<F>,
    ) {
        Self::matmul_internal_w(r1cs, next_var, state, internal_diag, witness);
        for i in 0..WIDTH {
            state[i] = Self::mul_const_w(r1cs, next_var, state[i], monty_inv, witness);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use p3_symmetric::Permutation;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use sp1_stark::BabyBearPoseidon2Inner;

    #[test]
    fn test_round_constants_loaded() {
        let rc = get_round_constants::<BabyBear>();
        assert_eq!(rc.len(), 30);
        
        // Verify first constant of round 0 (need from_wrapped_u32 as values may exceed modulus)
        assert_eq!(rc[0][0], BabyBear::from_wrapped_u32(2110014213));
        // Verify last constant of round 29
        assert_eq!(rc[29][15], BabyBear::from_wrapped_u32(3799795076));
    }

    #[test]
    fn test_sbox_constraints() {
        // Verify that x^7 is correctly constrained
        let mut r1cs = R1CS::<BabyBear>::new();
        let mut next_var = 1;
        
        // Allocate input variable
        let x = next_var;
        next_var += 1;
        r1cs.num_vars = next_var;
        
        // Apply S-box
        let x7 = Poseidon2R1CS::<BabyBear>::sbox_single(&mut r1cs, &mut next_var, x);
        
        // Should have 4 multiplication constraints (x², x⁴, x⁶, x⁷)
        assert_eq!(r1cs.num_constraints, 4);
        
        // Verify with a concrete value
        let test_val = BabyBear::from_canonical_u64(7);
        let expected = test_val * test_val * test_val * test_val * test_val * test_val * test_val;
        
        // Build witness
        let mut witness = vec![BabyBear::one(); r1cs.num_vars]; // witness[0] = 1
        witness[x] = test_val;
        
        // Compute intermediate values
        let x2_val = test_val * test_val;
        let x4_val = x2_val * x2_val;
        let x6_val = x4_val * x2_val;
        let x7_val = x6_val * test_val;
        
        // Fill in intermediates (indices 2, 3, 4, 5 based on allocation order)
        witness[2] = x2_val;
        witness[3] = x4_val;
        witness[4] = x6_val;
        witness[5] = x7_val;
        
        assert!(r1cs.is_satisfied(&witness));
        assert_eq!(witness[x7], expected);
    }

    #[test]
    fn test_poseidon2_matches_runtime_perm() {
        // This must match exactly what the recursion runtime uses:
        // `BabyBearPoseidon2Inner::new().perm`.
        let perm = BabyBearPoseidon2Inner::new().perm;

        let mut rng = StdRng::seed_from_u64(0xC0FFEE);
        for _ in 0..10 {
            // Random BabyBear state as canonical u32 -> BabyBear.
            let input: [BabyBear; WIDTH] = core::array::from_fn(|_| {
                // Use wrapped to allow any u32.
                BabyBear::from_wrapped_u32(rng.gen::<u32>())
            });
            let expected = perm.permute(input);

            // Build a standalone R1CS + witness for our expansion.
            let mut r1cs = R1CS::<BabyBear>::new();
            let mut next_var: usize = 1;

            // Allocate 16 input variables: indices 1..=16.
            let input_state: Vec<usize> = (0..WIDTH).map(|_| {
                let idx = next_var;
                next_var += 1;
                r1cs.num_vars = next_var;
                idx
            }).collect();

            let mut witness: Vec<BabyBear> = vec![BabyBear::one()];
            witness.resize(next_var, BabyBear::zero());
            for i in 0..WIDTH {
                witness[input_state[i]] = input[i];
            }

            let out_state = Poseidon2R1CS::<BabyBear>::expand_permute_babybear_with_witness(
                &mut r1cs,
                &mut next_var,
                &input_state,
                &mut witness,
            );
            r1cs.num_vars = next_var;
            witness.resize(next_var, BabyBear::zero());

            // Check R1CS satisfiable and outputs match expected permutation.
            assert!(r1cs.is_satisfied(&witness));
            for i in 0..WIDTH {
                assert_eq!(witness[out_state[i]], expected[i]);
            }
        }
    }
}
