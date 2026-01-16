//! Integration tests for R1CS compiler.
//!
//! These tests verify that the R1CS data structures and Poseidon2 expansion work correctly.

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::{AbstractField, PrimeField32};

    use crate::config::OuterConfig;
    use crate::ir::Var;
    use crate::r1cs::compiler::R1CSCompiler;
    use crate::r1cs::types::{R1CS, SparseRow};
    use crate::r1cs::poseidon2::{Poseidon2R1CS, WIDTH};
    use crate::r1cs::lf::{
        lift_r1cs_to_lf_with_linear_carries, lift_r1cs_to_lf_with_linear_carries_and_witness,
    };

    type F = BabyBear;

    #[test]
    fn test_public_inputs_are_prefix_indices() {
        // Regression test for the R1CS format contract:
        // public inputs occupy indices 1..=num_public.
        //
        // We model a minimal program that marks `var7` as a committed "public input" via
        // CircuitCommitVkeyHash, and rely on `get_value` to provide its value.
        //
        // The compiler must allocate `var7` into index 1 (public prefix).
        let v7 = Var::<p3_bls12_377_fr::Bls12377Fr>::new(7, core::ptr::null_mut());

        let ops = vec![
            // Mark var7 as a public/committed input.
            crate::ir::DslIr::<OuterConfig>::CircuitCommitVkeyHash(v7),
        ];

        let mut get_value = |id: &str| -> Option<BabyBear> {
            match id {
                "var7" => Some(BabyBear::from_canonical_u64(8)),
                _ => Some(BabyBear::zero()),
            }
        };
        let mut next_hint_felt = || -> Option<BabyBear> { None };
        let mut next_hint_ext = || -> Option<[BabyBear; 4]> { None };

        let (compiler, witness) = R1CSCompiler::<OuterConfig>::compile_with_witness(
            ops,
            &mut get_value,
            &mut next_hint_felt,
            &mut next_hint_ext,
        );

        assert_eq!(compiler.r1cs.num_public, 1, "expected exactly one public input");
        assert_eq!(compiler.vkey_hash_idx, Some(1), "committed var must be at index 1");
        assert_eq!(compiler.public_inputs, vec![1], "public input indices must be prefix");
        assert_eq!(
            compiler.var_map.get("var7").copied(),
            Some(1),
            "var7 must map to public prefix index 1"
        );
        assert_eq!(witness[0], BabyBear::one());
        assert_eq!(witness[1], BabyBear::from_canonical_u64(8), "public var7 value");
        assert_eq!(witness.len(), compiler.r1cs.num_vars, "witness length must match num_vars");
    }

    #[test]
    fn test_num2bits_v2_f_rejects_noncanonical_modulus_representation() {
        // Regression test: `CircuitV2HintBitsF` must enforce canonicality for 31-bit
        // decompositions (match `circuit/builder.rs::num2bits_v2_f`).
        //
        // Without the modulus check, the following would be satisfiable:
        // - value = 0 (in BabyBear field)
        // - bits represent the integer p (BabyBear modulus), which is congruent to 0 mod p
        //
        // The additional "top 4 bits" check must reject this non-canonical bitstring.
        use crate::ir::{DslIr, Felt};
        const P_BB: u64 = 2_013_265_921;

        // One felt value and 31 output bits.
        let value = Felt::<BabyBear>::new(1000, core::ptr::null_mut());
        let bits: Vec<Felt<BabyBear>> = (0..31)
            .map(|i| Felt::<BabyBear>::new(2000 + i as u32, core::ptr::null_mut()))
            .collect();

        let ops = vec![DslIr::<OuterConfig>::CircuitV2HintBitsF(bits.clone(), value)];

        let mut get_value = |id: &str| -> Option<BabyBear> {
            if id == "felt1000" {
                Some(BabyBear::zero())
            } else {
                Some(BabyBear::zero())
            }
        };
        let mut next_hint_felt = || -> Option<BabyBear> { None };
        let mut next_hint_ext = || -> Option<[BabyBear; 4]> { None };

        let (compiler, witness_ok) = R1CSCompiler::<OuterConfig>::compile_with_witness(
            ops,
            &mut get_value,
            &mut next_hint_felt,
            &mut next_hint_ext,
        );
        assert!(compiler.r1cs.is_satisfied(&witness_ok));

        // Build a cheating witness: set bits to represent integer p, but keep value = 0.
        let mut witness_bad = witness_ok.clone();
        let value_idx = *compiler
            .var_map
            .get("felt1000")
            .expect("value felt index should exist");
        witness_bad[value_idx] = BabyBear::zero();

        for (i, b) in bits.iter().enumerate() {
            let idx = *compiler
                .var_map
                .get(&b.id())
                .unwrap_or_else(|| panic!("bit id missing from var_map: {}", b.id()));
            let bit = (P_BB >> i) & 1;
            witness_bad[idx] = BabyBear::from_canonical_u64(bit);
        }

        assert!(
            !compiler.r1cs.is_satisfied(&witness_bad),
            "non-canonical bits encoding p should be rejected"
        );
    }

    #[test]
    fn test_num2bits_v2_f_accepts_canonical_p_minus_1() {
        // Regression test: witness generation + canonicality constraints must be consistent
        // for the corner value p-1 = 2^31 - 2^27 (top 4 bits are 1, bottom 27 bits are 0).
        use crate::ir::{DslIr, Felt};
        const P_MINUS_1: u64 = 2_013_265_920;

        let value = Felt::<BabyBear>::new(3000, core::ptr::null_mut());
        let bits: Vec<Felt<BabyBear>> = (0..31)
            .map(|i| Felt::<BabyBear>::new(4000 + i as u32, core::ptr::null_mut()))
            .collect();

        let ops = vec![DslIr::<OuterConfig>::CircuitV2HintBitsF(bits, value)];

        let mut get_value = |id: &str| -> Option<BabyBear> {
            if id == "felt3000" {
                Some(BabyBear::from_canonical_u64(P_MINUS_1))
            } else {
                Some(BabyBear::zero())
            }
        };
        let mut next_hint_felt = || -> Option<BabyBear> { None };
        let mut next_hint_ext = || -> Option<[BabyBear; 4]> { None };

        let (compiler, witness) = R1CSCompiler::<OuterConfig>::compile_with_witness(
            ops,
            &mut get_value,
            &mut next_hint_felt,
            &mut next_hint_ext,
        );
        assert!(
            compiler.r1cs.is_satisfied(&witness),
            "canonical p-1 decomposition should satisfy constraints"
        );
    }

    #[test]
    fn test_lift_refactor_digest_matches() {
        // Toy satisfied R1CS: (x) * (y) = z, with x=3,y=5,z=15.
        // This constraint is not a skip pattern, so it will be lifted and will introduce 1 aux var.
        let mut r1cs = R1CS::<F>::new();
        r1cs.num_vars = 4; // [1, x, y, z]
        r1cs.add_constraint(
            SparseRow::single(1),
            SparseRow::single(2),
            SparseRow::single(3),
        );

        let mut witness = vec![F::one(); r1cs.num_vars];
        witness[1] = F::from_canonical_u64(3);
        witness[2] = F::from_canonical_u64(5);
        witness[3] = F::from_canonical_u64(15);
        assert!(r1cs.is_satisfied(&witness));

        let (r1lf_a, _stats_a) = lift_r1cs_to_lf_with_linear_carries(&r1cs);
        let (r1lf_b, _stats_b, w_lf_u64) =
            lift_r1cs_to_lf_with_linear_carries_and_witness(&r1cs, &witness).unwrap();

        assert_eq!(r1lf_a.digest(), r1lf_b.digest(), "R1LF digest must match between lift entrypoints");
        assert_eq!(w_lf_u64.len(), r1lf_b.num_vars, "lifted witness must match R1LF.num_vars");
    }

    #[test]
    fn test_poseidon2_sbox_constraint_count() {
        // The S-box x^7 should produce exactly 4 multiplication constraints
        let mut r1cs = R1CS::<F>::new();
        let mut next_var = 1;
        
        // Allocate input
        let x = next_var;
        next_var += 1;
        r1cs.num_vars = next_var;
        
        // Apply S-box
        let _x7 = Poseidon2R1CS::<F>::sbox_single(&mut r1cs, &mut next_var, x);
        
        assert_eq!(r1cs.num_constraints, 4, "S-box x^7 should have exactly 4 multiplication constraints");
    }

    #[test]
    fn test_poseidon2_sbox_correctness() {
        // Verify S-box produces correct value
        let mut r1cs = R1CS::<F>::new();
        let mut next_var = 1;
        
        let x = next_var;
        next_var += 1;
        r1cs.num_vars = next_var;
        
        let x7 = Poseidon2R1CS::<F>::sbox_single(&mut r1cs, &mut next_var, x);
        
        // Test with value 3
        let input_val = F::from_canonical_u64(3);
        let expected = input_val * input_val * input_val * input_val * input_val * input_val * input_val;
        
        // Build witness
        let mut witness = vec![F::one(); r1cs.num_vars];
        witness[x] = input_val;
        
        // Compute intermediates
        let x2 = input_val * input_val;
        let x4 = x2 * x2;
        let x6 = x4 * x2;
        let x7_val = x6 * input_val;
        
        witness[2] = x2;
        witness[3] = x4;
        witness[4] = x6;
        witness[5] = x7_val;
        
        assert!(r1cs.is_satisfied(&witness), "S-box witness should satisfy constraints");
        assert_eq!(witness[x7], expected, "S-box output should be x^7");
    }

    #[test]
    fn test_poseidon2_full_permutation_constraint_count() {
        // Full Poseidon2 permutation should have a known constraint count
        let mut r1cs = R1CS::<F>::new();
        let mut next_var = 1;
        
        // Allocate 16 input variables
        let input_state: Vec<usize> = (0..WIDTH).map(|_| {
            let idx = next_var;
            next_var += 1;
            idx
        }).collect();
        r1cs.num_vars = next_var;
        
        // Expand permutation
        let _output_state = Poseidon2R1CS::<F>::expand_permute_babybear(&mut r1cs, &mut next_var, &input_state);
        
        // Poseidon2 with WIDTH=16, 8 external rounds, 13 internal rounds should produce many constraints
        assert!(r1cs.num_constraints > 500, 
            "Poseidon2 should have >500 constraints, got {}", r1cs.num_constraints);
        
        println!("Poseidon2 permutation: {} constraints, {} variables", 
            r1cs.num_constraints, r1cs.num_vars);
    }

    #[test]
    fn test_r1cs_digest_determinism() {
        // Same R1CS should produce same digest
        let mut r1cs1 = R1CS::<F>::new();
        let mut r1cs2 = R1CS::<F>::new();
        
        // Add same constraint to both
        r1cs1.add_constraint(
            SparseRow::single(0),
            SparseRow::single(1),
            SparseRow::single(2),
        );
        r1cs1.num_vars = 3;
        
        r1cs2.add_constraint(
            SparseRow::single(0),
            SparseRow::single(1),
            SparseRow::single(2),
        );
        r1cs2.num_vars = 3;
        
        assert_eq!(r1cs1.digest(), r1cs2.digest(), "Same R1CS should have same digest");
    }

    #[test]
    fn test_r1cs_digest_sensitivity() {
        // Different R1CS should produce different digest
        let mut r1cs1 = R1CS::<F>::new();
        let mut r1cs2 = R1CS::<F>::new();

        r1cs1.add_constraint(
            SparseRow::single(0),
            SparseRow::single(1),
            SparseRow::single(2),
        );
        r1cs1.num_vars = 3;
        
        // Different coefficient
        r1cs2.add_constraint(
            SparseRow::single(0),
            SparseRow::single_with_coeff(1, F::from_canonical_u64(2)),
            SparseRow::single(2),
        );
        r1cs2.num_vars = 3;
        
        assert_ne!(r1cs1.digest(), r1cs2.digest(), "Different R1CS should have different digest");
    }

    #[test]
    fn test_r1cs_satisfaction_simple() {
        // Test that a simple R1CS can be satisfied
        let mut r1cs = R1CS::<F>::new();
        
        // Constraint: 1 * x = y (copy)
        r1cs.add_constraint(
            SparseRow::single(0), // 1
            SparseRow::single(1), // x
            SparseRow::single(2), // y
        );
        r1cs.num_vars = 3;
        
        // Witness: [1, 5, 5] should satisfy 1 * 5 = 5
        let witness = vec![F::one(), F::from_canonical_u64(5), F::from_canonical_u64(5)];
        assert!(r1cs.is_satisfied(&witness));
        
        // Witness: [1, 5, 6] should NOT satisfy 1 * 5 = 6
        let bad_witness = vec![F::one(), F::from_canonical_u64(5), F::from_canonical_u64(6)];
        assert!(!r1cs.is_satisfied(&bad_witness));
    }

    #[test]
    fn test_r1cs_multiplication_constraint() {
        // Test a * b = c constraint
        let mut r1cs = R1CS::<F>::new();
        
        r1cs.add_constraint(
            SparseRow::single(1), // a
            SparseRow::single(2), // b  
            SparseRow::single(3), // c
        );
        r1cs.num_vars = 4;
        
        // 3 * 7 = 21
        let witness = vec![
            F::one(), 
            F::from_canonical_u64(3), 
            F::from_canonical_u64(7), 
            F::from_canonical_u64(21)
        ];
        assert!(r1cs.is_satisfied(&witness));
    }

    #[test]
    fn test_r1cs_linear_combination() {
        // Test (a + b) * 1 = c constraint (linear combination)
        let mut r1cs = R1CS::<F>::new();
        
        // (a + b) * 1 = c
        let mut lhs = SparseRow::new();
        lhs.add_term(1, F::one()); // a
        lhs.add_term(2, F::one()); // b
        
        r1cs.add_constraint(
            lhs,
            SparseRow::single(0), // 1
            SparseRow::single(3), // c
        );
        r1cs.num_vars = 4;
        
        // 5 + 7 = 12
        let witness = vec![
            F::one(),
            F::from_canonical_u64(5),
            F::from_canonical_u64(7),
            F::from_canonical_u64(12)
        ];
        assert!(r1cs.is_satisfied(&witness));
    }

    #[test]
    fn test_sparse_row_evaluation() {
        // Test SparseRow evaluation
        let mut row = SparseRow::<F>::new();
        row.add_term(0, F::from_canonical_u64(2)); // 2 * w[0]
        row.add_term(1, F::from_canonical_u64(3)); // 3 * w[1]
        row.add_term(2, F::from_canonical_u64(5)); // 5 * w[2]
        
        let witness = vec![
            F::from_canonical_u64(1),  // w[0] = 1
            F::from_canonical_u64(10), // w[1] = 10
            F::from_canonical_u64(100),// w[2] = 100
        ];
        
        // 2*1 + 3*10 + 5*100 = 2 + 30 + 500 = 532
        let result = row.evaluate(&witness);
        assert_eq!(result, F::from_canonical_u64(532));
    }

    #[test]
    fn test_extension_mul_constraint_count() {
        // Extension multiplication in BabyBear (degree 4) should use 16 base muls
        // a * b in F_p^4 where u^4 = 11
        // Result[k] = sum_{i+j=k} a[i]*b[j] + 11 * sum_{i+j=k+4} a[i]*b[j]
        
        // We can manually construct the R1CS for this
        let mut r1cs = R1CS::<F>::new();
        let mut next_var = 1;
        
        // Allocate extension elements a, b (4 components each)
        let a: [usize; 4] = [next_var, next_var+1, next_var+2, next_var+3];
        next_var += 4;
        let b: [usize; 4] = [next_var, next_var+1, next_var+2, next_var+3];
        next_var += 4;
        let c: [usize; 4] = [next_var, next_var+1, next_var+2, next_var+3];
        next_var += 4;
        r1cs.num_vars = next_var;
        
        // Allocate products a[i] * b[j]
        let mut products = [[0usize; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                products[i][j] = next_var;
                r1cs.add_constraint(
                    SparseRow::single(a[i]),
                    SparseRow::single(b[j]),
                    SparseRow::single(next_var),
                );
                next_var += 1;
            }
        }
        r1cs.num_vars = next_var;
        
        // Should have 16 multiplication constraints
        assert_eq!(r1cs.num_constraints, 16);
        
        // Then add linear combinations to compute c[k]
        let nr = F::from_canonical_u64(11);
        for k in 0..4 {
            let mut terms = SparseRow::new();
            for i in 0..4 {
                for j in 0..4 {
                    let idx = i + j;
                    if idx == k {
                        terms.add_term(products[i][j], F::one());
                    } else if idx == k + 4 {
                        terms.add_term(products[i][j], nr);
                    }
                }
            }
            r1cs.add_constraint(
                SparseRow::single(0),
                terms,
                SparseRow::single(c[k]),
            );
        }
        
        // Total: 16 muls + 4 linear combinations = 20 constraints
        assert_eq!(r1cs.num_constraints, 20);
    }

    /// Helper: Extension field multiplication in BabyBear (u^4 = 11)
    fn ext_mul(a: [F; 4], b: [F; 4]) -> [F; 4] {
        let nr = F::from_canonical_u64(11);
        let mut c = [F::zero(); 4];
        for i in 0..4 {
            for j in 0..4 {
                let prod = a[i] * b[j];
                let idx = i + j;
                if idx < 4 {
                    c[idx] += prod;
                } else {
                    c[idx - 4] += prod * nr;
                }
            }
        }
        c
    }

    /// Helper: Extension field subtraction
    fn ext_sub(a: [F; 4], b: [F; 4]) -> [F; 4] {
        [a[0] - b[0], a[1] - b[1], a[2] - b[2], a[3] - b[3]]
    }

    /// Helper: Embed base field into extension (BinomialExtension::from_base)
    fn from_base(x: F) -> [F; 4] {
        [x, F::zero(), F::zero(), F::zero()]
    }

    #[test]
    fn test_fri_fold_constraint_sign() {
        // Test the FRI fold constraint with correct sign:
        //   (new_ro - old_ro) * (x - z) = (p_at_x - p_at_z) * old_alpha_pow
        //
        // This matches recursion-core/src/chips/fri_fold.rs line 330:
        //   (new_ro - old_ro) * (BinomialExtension::from_base(x) - z) = (p_at_x - p_at_z) * old_alpha_pow

        // Choose concrete values
        let x = F::from_canonical_u64(7);
        let z: [F; 4] = [
            F::from_canonical_u64(3),
            F::from_canonical_u64(5),
            F::from_canonical_u64(2),
            F::from_canonical_u64(1),
        ];
        let p_at_x: [F; 4] = [
            F::from_canonical_u64(100),
            F::from_canonical_u64(200),
            F::from_canonical_u64(300),
            F::from_canonical_u64(400),
        ];
        let p_at_z: [F; 4] = [
            F::from_canonical_u64(10),
            F::from_canonical_u64(20),
            F::from_canonical_u64(30),
            F::from_canonical_u64(40),
        ];
        let old_alpha_pow: [F; 4] = [
            F::from_canonical_u64(2),
            F::from_canonical_u64(0),
            F::from_canonical_u64(0),
            F::from_canonical_u64(0),
        ];
        let _old_ro: [F; 4] = [
            F::from_canonical_u64(1000),
            F::from_canonical_u64(2000),
            F::from_canonical_u64(3000),
            F::from_canonical_u64(4000),
        ];

        // Compute x - z = from_base(x) - z
        let x_minus_z = ext_sub(from_base(x), z);
        
        // Compute (p_at_x - p_at_z) * old_alpha_pow = rhs
        let diff_p = ext_sub(p_at_x, p_at_z);
        let _rhs = ext_mul(diff_p, old_alpha_pow);
        
        // Compute new_ro such that (new_ro - old_ro) * (x - z) = rhs
        // => diff_ro * (x - z) = rhs
        // => diff_ro = rhs / (x - z)
        // For testing, we compute diff_ro directly and derive new_ro
        
        // We need to find diff_ro such that diff_ro * (x - z) = rhs
        // This requires extension field division, which is complex.
        // Instead, let's verify the equation with known values by checking:
        // rhs == (new_ro - old_ro) * (x - z)

        // For simplicity, let's pick diff_ro = [1, 0, 0, 0] and compute rhs = diff_ro * (x - z)
        let diff_ro: [F; 4] = [F::one(), F::zero(), F::zero(), F::zero()];
        let _computed_rhs = ext_mul(diff_ro, x_minus_z);
        
        // Now we know: diff_ro * (x - z) = computed_rhs
        // We need: (p_at_x - p_at_z) * old_alpha_pow = computed_rhs
        // So pick p_at_x, p_at_z, old_alpha_pow such that this holds.
        
        // Actually, let's do it the easy way: verify the constraint structure is correct
        // by building an R1CS that mirrors the compiler's output and checking satisfaction.
        
        // Build R1CS manually for one FRI fold row
        let mut r1cs = R1CS::<F>::new();
        let mut next_var = 1;
        
        // Allocate variables
        // x (felt)
        let x_idx = next_var; next_var += 1;
        // z (ext)
        let z_idx: [usize; 4] = [next_var, next_var+1, next_var+2, next_var+3]; next_var += 4;
        // p_at_x (ext)
        let p_at_x_idx: [usize; 4] = [next_var, next_var+1, next_var+2, next_var+3]; next_var += 4;
        // p_at_z (ext)
        let p_at_z_idx: [usize; 4] = [next_var, next_var+1, next_var+2, next_var+3]; next_var += 4;
        // old_alpha_pow (ext)
        let alpha_pow_idx: [usize; 4] = [next_var, next_var+1, next_var+2, next_var+3]; next_var += 4;
        // old_ro (ext)
        let old_ro_idx: [usize; 4] = [next_var, next_var+1, next_var+2, next_var+3]; next_var += 4;
        // new_ro (ext) - what we're solving for
        let new_ro_idx: [usize; 4] = [next_var, next_var+1, next_var+2, next_var+3]; next_var += 4;
        
        r1cs.num_vars = next_var;
        
        // Build constraint: (new_ro - old_ro) * (x - z) = (p_at_x - p_at_z) * old_alpha_pow
        
        // Step 1: diff_p = p_at_x - p_at_z
        let diff_p_idx: [usize; 4] = [next_var, next_var+1, next_var+2, next_var+3]; next_var += 4;
        for i in 0..4 {
            let mut row = SparseRow::new();
            row.add_term(p_at_x_idx[i], F::one());
            row.add_term(p_at_z_idx[i], -F::one());
            r1cs.add_constraint(SparseRow::single(0), row, SparseRow::single(diff_p_idx[i]));
        }
        
        // Step 2: rhs = diff_p * old_alpha_pow (extension multiplication)
        let rhs_idx: [usize; 4] = [next_var, next_var+1, next_var+2, next_var+3]; next_var += 4;
        // Need 16 products
        let mut prods = [[0usize; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                prods[i][j] = next_var;
                r1cs.add_constraint(
                    SparseRow::single(diff_p_idx[i]),
                    SparseRow::single(alpha_pow_idx[j]),
                    SparseRow::single(next_var),
                );
                next_var += 1;
            }
        }
        // Combine products into rhs
        let nr = F::from_canonical_u64(11);
        for k in 0..4 {
            let mut terms = SparseRow::new();
            for i in 0..4 {
                for j in 0..4 {
                    let idx = i + j;
                    if idx == k {
                        terms.add_term(prods[i][j], F::one());
                    } else if idx == k + 4 {
                        terms.add_term(prods[i][j], nr);
                    }
                }
            }
            r1cs.add_constraint(SparseRow::single(0), terms, SparseRow::single(rhs_idx[k]));
        }
        
        // Step 3: diff_ro = new_ro - old_ro
        let diff_ro_idx: [usize; 4] = [next_var, next_var+1, next_var+2, next_var+3]; next_var += 4;
        for i in 0..4 {
            let mut row = SparseRow::new();
            row.add_term(new_ro_idx[i], F::one());
            row.add_term(old_ro_idx[i], -F::one());
            r1cs.add_constraint(SparseRow::single(0), row, SparseRow::single(diff_ro_idx[i]));
        }
        
        // Step 4: x_minus_z = from_base(x) - z
        // x_minus_z[0] = x - z[0], x_minus_z[i] = -z[i] for i > 0
        let x_minus_z_idx: [usize; 4] = [next_var, next_var+1, next_var+2, next_var+3]; next_var += 4;
        {
            let mut row = SparseRow::new();
            row.add_term(x_idx, F::one());
            row.add_term(z_idx[0], -F::one());
            r1cs.add_constraint(SparseRow::single(0), row, SparseRow::single(x_minus_z_idx[0]));
        }
        for i in 1..4 {
            let mut row = SparseRow::new();
            row.add_term(z_idx[i], -F::one());
            r1cs.add_constraint(SparseRow::single(0), row, SparseRow::single(x_minus_z_idx[i]));
        }
        
        // Step 5: diff_ro * x_minus_z = rhs (extension multiplication check)
        // Need 16 products
        let mut check_prods = [[0usize; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                check_prods[i][j] = next_var;
                r1cs.add_constraint(
                    SparseRow::single(diff_ro_idx[i]),
                    SparseRow::single(x_minus_z_idx[j]),
                    SparseRow::single(next_var),
                );
                next_var += 1;
            }
        }
        // Check products sum to rhs
        for k in 0..4 {
            let mut terms = SparseRow::new();
            for i in 0..4 {
                for j in 0..4 {
                    let idx = i + j;
                    if idx == k {
                        terms.add_term(check_prods[i][j], F::one());
                    } else if idx == k + 4 {
                        terms.add_term(check_prods[i][j], nr);
                    }
                }
            }
            r1cs.add_constraint(SparseRow::single(0), terms, SparseRow::single(rhs_idx[k]));
        }
        
        r1cs.num_vars = next_var;
        
        // Now build a witness with concrete values
        // Pick simple values: x=7, z=[3,0,0,0], p_at_x=[10,0,0,0], p_at_z=[2,0,0,0], 
        // old_alpha_pow=[1,0,0,0], old_ro=[0,0,0,0]
        let x_val = F::from_canonical_u64(7);
        let z_val: [F; 4] = [F::from_canonical_u64(3), F::zero(), F::zero(), F::zero()];
        let p_at_x_val: [F; 4] = [F::from_canonical_u64(10), F::zero(), F::zero(), F::zero()];
        let p_at_z_val: [F; 4] = [F::from_canonical_u64(2), F::zero(), F::zero(), F::zero()];
        let alpha_pow_val: [F; 4] = [F::one(), F::zero(), F::zero(), F::zero()];
        let old_ro_val: [F; 4] = [F::zero(), F::zero(), F::zero(), F::zero()];
        
        // Compute derived values
        let diff_p_val = ext_sub(p_at_x_val, p_at_z_val); // [8, 0, 0, 0]
        let rhs_val = ext_mul(diff_p_val, alpha_pow_val);  // [8, 0, 0, 0]
        let x_minus_z_val = ext_sub(from_base(x_val), z_val); // [4, 0, 0, 0]
        
        // Solve for diff_ro: diff_ro * x_minus_z = rhs
        // With x_minus_z = [4, 0, 0, 0] and rhs = [8, 0, 0, 0]
        // diff_ro[0] * 4 = 8 => diff_ro[0] = 2
        let diff_ro_val: [F; 4] = [F::from_canonical_u64(2), F::zero(), F::zero(), F::zero()];
        let new_ro_val: [F; 4] = [
            old_ro_val[0] + diff_ro_val[0],
            old_ro_val[1] + diff_ro_val[1],
            old_ro_val[2] + diff_ro_val[2],
            old_ro_val[3] + diff_ro_val[3],
        ]; // [2, 0, 0, 0]
        
        // Verify the equation holds
        let check_lhs = ext_mul(diff_ro_val, x_minus_z_val);
        assert_eq!(check_lhs, rhs_val, "Sanity check: diff_ro * (x-z) should equal rhs");
        
        // Build witness vector
        let mut witness = vec![F::zero(); r1cs.num_vars];
        witness[0] = F::one(); // constant 1
        witness[x_idx] = x_val;
        for i in 0..4 {
            witness[z_idx[i]] = z_val[i];
            witness[p_at_x_idx[i]] = p_at_x_val[i];
            witness[p_at_z_idx[i]] = p_at_z_val[i];
            witness[alpha_pow_idx[i]] = alpha_pow_val[i];
            witness[old_ro_idx[i]] = old_ro_val[i];
            witness[new_ro_idx[i]] = new_ro_val[i];
            witness[diff_p_idx[i]] = diff_p_val[i];
            witness[rhs_idx[i]] = rhs_val[i];
            witness[diff_ro_idx[i]] = diff_ro_val[i];
            witness[x_minus_z_idx[i]] = x_minus_z_val[i];
        }
        
        // Fill in product witnesses
        for i in 0..4 {
            for j in 0..4 {
                witness[prods[i][j]] = diff_p_val[i] * alpha_pow_val[j];
                witness[check_prods[i][j]] = diff_ro_val[i] * x_minus_z_val[j];
            }
        }
        
        // Verify R1CS is satisfied
        assert!(r1cs.is_satisfied(&witness), "FRI fold constraint with (x-z) should be satisfied");
        
        // Now verify that using (z-x) instead would FAIL
        // Change x_minus_z to z_minus_x
        let z_minus_x_val = ext_sub(z_val, from_base(x_val)); // [-4, 0, 0, 0]
        for i in 0..4 {
            witness[x_minus_z_idx[i]] = z_minus_x_val[i];
        }
        // Recompute check products with wrong sign
        for i in 0..4 {
            for j in 0..4 {
                witness[check_prods[i][j]] = diff_ro_val[i] * z_minus_x_val[j];
            }
        }
        
        // This should fail because the sign is wrong
        assert!(!r1cs.is_satisfied(&witness), "FRI fold constraint with (z-x) should NOT be satisfied");
        
        println!("FRI fold sign test passed: (x-z) works, (z-x) fails");
    }

    #[test]
    fn test_exp_reverse_bits_constraint() {
        // Test the ExpReverseBits recurrence:
        //   accum_0 = 1
        //   for bit in bits:
        //     accum = accum^2 * (bit ? base : 1)
        
        let base = F::from_canonical_u64(3);
        let bits = [F::one(), F::zero(), F::one()]; // binary: 101 = 5
        
        // Expected: base^5 = 3^5 = 243
        let expected = base * base * base * base * base;
        assert_eq!(expected, F::from_canonical_u64(243));
        
        // Trace the recurrence:
        // accum_0 = 1
        // bit=1: accum = 1^2 * 3 = 3
        // bit=0: accum = 3^2 * 1 = 9
        // bit=1: accum = 9^2 * 3 = 81 * 3 = 243
        let mut accum = F::one();
        for &bit in &bits {
            let accum_sq = accum * accum;
            let multiplier = if bit == F::one() { base } else { F::one() };
            accum = accum_sq * multiplier;
        }
        assert_eq!(accum, expected, "Recurrence should compute base^5 = 243");
        
        // Now build R1CS to verify constraint structure
        let mut r1cs = R1CS::<F>::new();
        let mut next_var = 1;
        
        // Allocate base
        let base_idx = next_var; next_var += 1;
        // Allocate bits
        let bit_indices: Vec<usize> = (0..3).map(|_| { let i = next_var; next_var += 1; i }).collect();
        // Output
        let output_idx = next_var; next_var += 1;
        
        r1cs.num_vars = next_var;
        
        // Trace through the recurrence building constraints
        let mut accum_idx: usize = 0; // starts at witness[0] = 1
        let mut intermediates = Vec::new();
        
        for &bit_idx in &bit_indices {
            // Boolean constraint: bit * (1 - bit) = 0
            // Equivalent: bit * bit = bit
            r1cs.add_constraint(
                SparseRow::single(bit_idx),
                SparseRow::single(bit_idx),
                SparseRow::single(bit_idx),
            );
            
            // accum_sq = accum * accum
            let accum_sq = next_var; next_var += 1;
            r1cs.add_constraint(
                SparseRow::single(accum_idx),
                SparseRow::single(accum_idx),
                SparseRow::single(accum_sq),
            );
            
            // multiplier = bit ? base : 1
            // (bit) * (base - 1) = (multiplier - 1)
            let multiplier = next_var; next_var += 1;
            let mut base_minus_one = SparseRow::new();
            base_minus_one.add_term(base_idx, F::one());
            base_minus_one.add_term(0, -F::one());
            let mut mult_minus_one = SparseRow::new();
            mult_minus_one.add_term(multiplier, F::one());
            mult_minus_one.add_term(0, -F::one());
            r1cs.add_constraint(
                SparseRow::single(bit_idx),
                base_minus_one,
                mult_minus_one,
            );
            
            // accum_next = accum_sq * multiplier
            let accum_next = next_var; next_var += 1;
            r1cs.add_constraint(
                SparseRow::single(accum_sq),
                SparseRow::single(multiplier),
                SparseRow::single(accum_next),
            );
            
            intermediates.push((accum_sq, multiplier, accum_next));
            accum_idx = accum_next;
        }
        
        // Final: output = accum
        r1cs.add_constraint(
            SparseRow::single(0),
            SparseRow::single(accum_idx),
            SparseRow::single(output_idx),
        );
        
        r1cs.num_vars = next_var;
        
        // Build witness
        let mut witness = vec![F::zero(); r1cs.num_vars];
        witness[0] = F::one();
        witness[base_idx] = base;
        witness[bit_indices[0]] = bits[0];
        witness[bit_indices[1]] = bits[1];
        witness[bit_indices[2]] = bits[2];
        witness[output_idx] = expected;
        
        // Fill in intermediates
        let mut acc = F::one();
        for (i, &bit) in bits.iter().enumerate() {
            let acc_sq = acc * acc;
            let mult = if bit == F::one() { base } else { F::one() };
            let acc_next = acc_sq * mult;
            
            witness[intermediates[i].0] = acc_sq;
            witness[intermediates[i].1] = mult;
            witness[intermediates[i].2] = acc_next;
            acc = acc_next;
        }
        
        assert!(r1cs.is_satisfied(&witness), "ExpReverseBits constraint should be satisfied");
        
        // Verify wrong output fails
        witness[output_idx] = F::from_canonical_u64(999);
        assert!(!r1cs.is_satisfied(&witness), "Wrong output should fail");
        
        println!("ExpReverseBits test passed: computes 3^5 = 243 correctly");
    }

    #[test]
    fn test_batch_fri_matches_chip() {
        // Test the BatchFRI constraint: acc = sum(alpha_pow[i] * (p_at_z[i] - from_base(p_at_x[i])))
        //
        // From recursion-core/src/chips/batch_fri.rs lines 222-244:
        //   First row:  acc = alpha_pow * (p_at_z - from_base(p_at_x))
        //   Other rows: acc = prev_acc + alpha_pow * (p_at_z - from_base(p_at_x))
        //
        // For N=2 elements:
        //   acc = alpha_pow[0] * (p_at_z[0] - from_base(p_at_x[0]))
        //       + alpha_pow[1] * (p_at_z[1] - from_base(p_at_x[1]))

        // Use N=2 for simplicity
        let n = 2;
        
        // Choose concrete values
        let alpha_pow_vals: [[F; 4]; 2] = [
            [F::from_canonical_u64(2), F::zero(), F::zero(), F::zero()],  // alpha_pow[0] = 2
            [F::from_canonical_u64(3), F::zero(), F::zero(), F::zero()],  // alpha_pow[1] = 3
        ];
        let p_at_z_vals: [[F; 4]; 2] = [
            [F::from_canonical_u64(10), F::from_canonical_u64(1), F::zero(), F::zero()],  // p_at_z[0] = [10, 1, 0, 0]
            [F::from_canonical_u64(20), F::zero(), F::from_canonical_u64(2), F::zero()],  // p_at_z[1] = [20, 0, 2, 0]
        ];
        let p_at_x_vals: [F; 2] = [
            F::from_canonical_u64(5),   // p_at_x[0] = 5
            F::from_canonical_u64(8),   // p_at_x[1] = 8
        ];

        // Compute expected acc
        // diff[0] = p_at_z[0] - from_base(p_at_x[0]) = [10-5, 1, 0, 0] = [5, 1, 0, 0]
        // term[0] = alpha_pow[0] * diff[0] = 2 * [5, 1, 0, 0] = [10, 2, 0, 0]
        // diff[1] = p_at_z[1] - from_base(p_at_x[1]) = [20-8, 0, 2, 0] = [12, 0, 2, 0]
        // term[1] = alpha_pow[1] * diff[1] = 3 * [12, 0, 2, 0] = [36, 0, 6, 0]
        // acc = term[0] + term[1] = [10+36, 2+0, 0+6, 0+0] = [46, 2, 6, 0]
        
        let diff_vals: [[F; 4]; 2] = [
            ext_sub(p_at_z_vals[0], from_base(p_at_x_vals[0])),
            ext_sub(p_at_z_vals[1], from_base(p_at_x_vals[1])),
        ];
        let term_vals: [[F; 4]; 2] = [
            ext_mul(alpha_pow_vals[0], diff_vals[0]),
            ext_mul(alpha_pow_vals[1], diff_vals[1]),
        ];
        let expected_acc = [
            term_vals[0][0] + term_vals[1][0],
            term_vals[0][1] + term_vals[1][1],
            term_vals[0][2] + term_vals[1][2],
            term_vals[0][3] + term_vals[1][3],
        ];
        
        // Sanity check
        assert_eq!(expected_acc[0], F::from_canonical_u64(46), "acc[0] should be 46");
        assert_eq!(expected_acc[1], F::from_canonical_u64(2), "acc[1] should be 2");
        assert_eq!(expected_acc[2], F::from_canonical_u64(6), "acc[2] should be 6");
        assert_eq!(expected_acc[3], F::zero(), "acc[3] should be 0");
        
        // Build R1CS mimicking compiler's CircuitV2BatchFRI
        let mut r1cs = R1CS::<F>::new();
        let mut next_var = 1;
        
        // Allocate input variables
        let mut alpha_pow_idx: Vec<[usize; 4]> = Vec::new();
        let mut p_at_z_idx: Vec<[usize; 4]> = Vec::new();
        let mut p_at_x_idx: Vec<usize> = Vec::new();
        
        for _ in 0..n {
            let ap: [usize; 4] = [next_var, next_var+1, next_var+2, next_var+3]; next_var += 4;
            alpha_pow_idx.push(ap);
            let pz: [usize; 4] = [next_var, next_var+1, next_var+2, next_var+3]; next_var += 4;
            p_at_z_idx.push(pz);
            let px = next_var; next_var += 1;
            p_at_x_idx.push(px);
        }
        
        // Output accumulator
        let acc_idx: [usize; 4] = [next_var, next_var+1, next_var+2, next_var+3]; next_var += 4;
        
        r1cs.num_vars = next_var;
        
        // Initialize running_sum to zero
        let mut running_sum_idx: Vec<usize> = (0..4).map(|_| {
            let idx = next_var; next_var += 1;
            r1cs.add_constraint(
                SparseRow::single(0),
                SparseRow::zero(),
                SparseRow::single(idx),
            );
            idx
        }).collect();
        r1cs.num_vars = next_var;
        
        // For each element, compute diff, term, and accumulate
        let nr = F::from_canonical_u64(11);
        let mut all_diff_idx: Vec<[usize; 4]> = Vec::new();
        let mut all_term_idx: Vec<[usize; 4]> = Vec::new();
        let mut all_products: Vec<[[usize; 4]; 4]> = Vec::new();
        
        for j in 0..n {
            // diff = p_at_z - from_base(p_at_x)
            let diff_idx: [usize; 4] = [next_var, next_var+1, next_var+2, next_var+3]; next_var += 4;
            
            // diff[0] = p_at_z[0] - p_at_x
            let mut diff0 = SparseRow::new();
            diff0.add_term(p_at_z_idx[j][0], F::one());
            diff0.add_term(p_at_x_idx[j], -F::one());
            r1cs.add_constraint(SparseRow::single(0), diff0, SparseRow::single(diff_idx[0]));
            
            // diff[1..4] = p_at_z[1..4]
            for i in 1..4 {
                r1cs.add_constraint(
                    SparseRow::single(0),
                    SparseRow::single(p_at_z_idx[j][i]),
                    SparseRow::single(diff_idx[i]),
                );
            }
            all_diff_idx.push(diff_idx);
            
            // term = alpha_pow * diff (extension multiplication)
            let term_idx: [usize; 4] = [next_var, next_var+1, next_var+2, next_var+3]; next_var += 4;
            
            // 16 products
            let mut products = [[0usize; 4]; 4];
            for i in 0..4 {
                for k in 0..4 {
                    products[i][k] = next_var;
                    r1cs.add_constraint(
                        SparseRow::single(alpha_pow_idx[j][i]),
                        SparseRow::single(diff_idx[k]),
                        SparseRow::single(next_var),
                    );
                    next_var += 1;
                }
            }
            // Combine into term
            for k in 0..4 {
                let mut terms = SparseRow::new();
                for i in 0..4 {
                    for jj in 0..4 {
                        let idx = i + jj;
                        if idx == k {
                            terms.add_term(products[i][jj], F::one());
                        } else if idx == k + 4 {
                            terms.add_term(products[i][jj], nr);
                        }
                    }
                }
                r1cs.add_constraint(SparseRow::single(0), terms, SparseRow::single(term_idx[k]));
            }
            all_term_idx.push(term_idx);
            all_products.push(products);
            
            // new_sum = running_sum + term
            let new_sum_idx: Vec<usize> = (0..4).map(|i| {
                let idx = next_var; next_var += 1;
                let mut sum = SparseRow::new();
                sum.add_term(running_sum_idx[i], F::one());
                sum.add_term(term_idx[i], F::one());
                r1cs.add_constraint(SparseRow::single(0), sum, SparseRow::single(idx));
                idx
            }).collect();
            running_sum_idx = new_sum_idx;
        }
        
        // Bind final sum to acc
        for i in 0..4 {
            r1cs.add_constraint(
                SparseRow::single(0),
                SparseRow::single(running_sum_idx[i]),
                SparseRow::single(acc_idx[i]),
            );
        }
        
        r1cs.num_vars = next_var;
        
        // Build witness
        let mut witness = vec![F::zero(); r1cs.num_vars];
        witness[0] = F::one();
        
        for j in 0..n {
            for i in 0..4 {
                witness[alpha_pow_idx[j][i]] = alpha_pow_vals[j][i];
                witness[p_at_z_idx[j][i]] = p_at_z_vals[j][i];
            }
            witness[p_at_x_idx[j]] = p_at_x_vals[j];
        }
        for i in 0..4 {
            witness[acc_idx[i]] = expected_acc[i];
        }
        
        // Fill running_sum initial (should be zero, already is)
        // Fill diff, term, products
        let mut run_sum = [F::zero(); 4];
        for j in 0..n {
            for i in 0..4 {
                witness[all_diff_idx[j][i]] = diff_vals[j][i];
                witness[all_term_idx[j][i]] = term_vals[j][i];
            }
            for i in 0..4 {
                for k in 0..4 {
                    witness[all_products[j][i][k]] = alpha_pow_vals[j][i] * diff_vals[j][k];
                }
            }
            // Update running sum
            for i in 0..4 {
                run_sum[i] += term_vals[j][i];
            }
        }
        // The intermediate running_sum variables need to be filled
        // We need to track where they are - but they were allocated dynamically.
        // Let's find them by scanning the allocation order.
        
        // Re-trace allocation to find running_sum positions
        // This is tricky. Let's simplify by checking satisfaction directly,
        // which will compute values from the constraints.
        
        // Actually, let's just verify the R1CS is satisfied with a complete witness
        // We need to fill in ALL intermediate variables correctly.
        
        // The initial running_sum was allocated at next_var after acc_idx,
        // which was [next_var, next_var+1, next_var+2, next_var+3] = [21, 22, 23, 24] (0-indexed: 1 + 4*4 + 2 + 4 = 23 is acc start)
        // Actually let's just trace through properly:
        // - var 0 = 1 (constant)
        // - vars 1-4: alpha_pow[0]
        // - vars 5-8: p_at_z[0]
        // - var 9: p_at_x[0]
        // - vars 10-13: alpha_pow[1]
        // - vars 14-17: p_at_z[1]
        // - var 18: p_at_x[1]
        // - vars 19-22: acc
        // - vars 23-26: running_sum_0 (initial zeros)
        // - vars 27-30: diff[0]
        // - vars 31-34: term[0]
        // - vars 35-50: products[0] (16 vars)
        // - vars 51-54: running_sum_1
        // - vars 55-58: diff[1]
        // - vars 59-62: term[1]
        // - vars 63-78: products[1] (16 vars)
        // - vars 79-82: running_sum_2 (final)

        // Fill running_sum[0] = [0,0,0,0]
        // running_sum[1] = term[0] = [10, 2, 0, 0]
        // running_sum[2] = term[0] + term[1] = expected_acc
        
        // The loop allocates: diff_idx, term_idx, products (16), then new_sum_idx
        // So for j=0:
        //   diff_idx = [27, 28, 29, 30]
        //   term_idx = [31, 32, 33, 34]
        //   products = vars 35..50
        //   new_sum_idx (running_sum after j=0) = [51, 52, 53, 54]
        // For j=1:
        //   diff_idx = [55, 56, 57, 58]
        //   term_idx = [59, 60, 61, 62]
        //   products = vars 63..78
        //   new_sum_idx (running_sum after j=1) = [79, 80, 81, 82]
        
        // Initial running_sum = [23, 24, 25, 26] = [0, 0, 0, 0]
        witness[23] = F::zero();
        witness[24] = F::zero();
        witness[25] = F::zero();
        witness[26] = F::zero();
        
        // After j=0: running_sum = term_vals[0]
        witness[51] = term_vals[0][0];
        witness[52] = term_vals[0][1];
        witness[53] = term_vals[0][2];
        witness[54] = term_vals[0][3];
        
        // After j=1: running_sum = expected_acc
        witness[79] = expected_acc[0];
        witness[80] = expected_acc[1];
        witness[81] = expected_acc[2];
        witness[82] = expected_acc[3];
        
        assert!(r1cs.is_satisfied(&witness), "BatchFRI constraint should be satisfied with correct witness");
        
        println!("BatchFRI test passed: acc = sum(alpha_pow * (p_at_z - p_at_x)) = [{}, {}, {}, {}]",
            expected_acc[0].as_canonical_u32(),
            expected_acc[1].as_canonical_u32(),
            expected_acc[2].as_canonical_u32(),
            expected_acc[3].as_canonical_u32());
    }

    #[test]
    fn test_batch_fri_rejects_wrong_acc() {
        // Same setup as test_batch_fri_matches_chip but with wrong accumulator
        let n = 2;
        
        let alpha_pow_vals: [[F; 4]; 2] = [
            [F::from_canonical_u64(2), F::zero(), F::zero(), F::zero()],
            [F::from_canonical_u64(3), F::zero(), F::zero(), F::zero()],
        ];
        let p_at_z_vals: [[F; 4]; 2] = [
            [F::from_canonical_u64(10), F::from_canonical_u64(1), F::zero(), F::zero()],
            [F::from_canonical_u64(20), F::zero(), F::from_canonical_u64(2), F::zero()],
        ];
        let p_at_x_vals: [F; 2] = [
            F::from_canonical_u64(5),
            F::from_canonical_u64(8),
        ];

        let diff_vals: [[F; 4]; 2] = [
            ext_sub(p_at_z_vals[0], from_base(p_at_x_vals[0])),
            ext_sub(p_at_z_vals[1], from_base(p_at_x_vals[1])),
        ];
        let term_vals: [[F; 4]; 2] = [
            ext_mul(alpha_pow_vals[0], diff_vals[0]),
            ext_mul(alpha_pow_vals[1], diff_vals[1]),
        ];
        let expected_acc = [
            term_vals[0][0] + term_vals[1][0],
            term_vals[0][1] + term_vals[1][1],
            term_vals[0][2] + term_vals[1][2],
            term_vals[0][3] + term_vals[1][3],
        ];
        
        // Build simplified R1CS - just test that final binding matters
        let mut r1cs = R1CS::<F>::new();
        let mut next_var = 1;
        
        // Allocate inputs
        let mut alpha_pow_idx: Vec<[usize; 4]> = Vec::new();
        let mut p_at_z_idx: Vec<[usize; 4]> = Vec::new();
        let mut p_at_x_idx: Vec<usize> = Vec::new();
        
        for _ in 0..n {
            let ap: [usize; 4] = [next_var, next_var+1, next_var+2, next_var+3]; next_var += 4;
            alpha_pow_idx.push(ap);
            let pz: [usize; 4] = [next_var, next_var+1, next_var+2, next_var+3]; next_var += 4;
            p_at_z_idx.push(pz);
            let px = next_var; next_var += 1;
            p_at_x_idx.push(px);
        }
        
        let acc_idx: [usize; 4] = [next_var, next_var+1, next_var+2, next_var+3]; next_var += 4;
        r1cs.num_vars = next_var;
        
        let nr = F::from_canonical_u64(11);
        
        // Initialize running_sum to zero
        let mut running_sum_idx: Vec<usize> = (0..4).map(|_| {
            let idx = next_var; next_var += 1;
            r1cs.add_constraint(SparseRow::single(0), SparseRow::zero(), SparseRow::single(idx));
            idx
        }).collect();
        r1cs.num_vars = next_var;
        
        for j in 0..n {
            // diff
            let diff_idx: [usize; 4] = [next_var, next_var+1, next_var+2, next_var+3]; next_var += 4;
            let mut diff0 = SparseRow::new();
            diff0.add_term(p_at_z_idx[j][0], F::one());
            diff0.add_term(p_at_x_idx[j], -F::one());
            r1cs.add_constraint(SparseRow::single(0), diff0, SparseRow::single(diff_idx[0]));
            for i in 1..4 {
                r1cs.add_constraint(SparseRow::single(0), SparseRow::single(p_at_z_idx[j][i]), SparseRow::single(diff_idx[i]));
            }
            
            // term = alpha_pow * diff
            let term_idx: [usize; 4] = [next_var, next_var+1, next_var+2, next_var+3]; next_var += 4;
            let mut products = [[0usize; 4]; 4];
            for i in 0..4 {
                for k in 0..4 {
                    products[i][k] = next_var;
                    r1cs.add_constraint(
                        SparseRow::single(alpha_pow_idx[j][i]),
                        SparseRow::single(diff_idx[k]),
                        SparseRow::single(next_var),
                    );
                    next_var += 1;
                }
            }
            for k in 0..4 {
                let mut terms = SparseRow::new();
                for i in 0..4 {
                    for jj in 0..4 {
                        let idx = i + jj;
                        if idx == k { terms.add_term(products[i][jj], F::one()); }
                        else if idx == k + 4 { terms.add_term(products[i][jj], nr); }
                    }
                }
                r1cs.add_constraint(SparseRow::single(0), terms, SparseRow::single(term_idx[k]));
            }
            
            // new_sum
            let new_sum_idx: Vec<usize> = (0..4).map(|i| {
                let idx = next_var; next_var += 1;
                let mut sum = SparseRow::new();
                sum.add_term(running_sum_idx[i], F::one());
                sum.add_term(term_idx[i], F::one());
                r1cs.add_constraint(SparseRow::single(0), sum, SparseRow::single(idx));
                idx
            }).collect();
            running_sum_idx = new_sum_idx;
        }
        
        // Bind final sum to acc
        for i in 0..4 {
            r1cs.add_constraint(SparseRow::single(0), SparseRow::single(running_sum_idx[i]), SparseRow::single(acc_idx[i]));
        }
        r1cs.num_vars = next_var;
        
        // Build correct witness first
        let mut witness = vec![F::zero(); r1cs.num_vars];
        witness[0] = F::one();
        
        for j in 0..n {
            for i in 0..4 {
                witness[alpha_pow_idx[j][i]] = alpha_pow_vals[j][i];
                witness[p_at_z_idx[j][i]] = p_at_z_vals[j][i];
            }
            witness[p_at_x_idx[j]] = p_at_x_vals[j];
        }
        for i in 0..4 {
            witness[acc_idx[i]] = expected_acc[i];
        }
        
        // Fill intermediates (same layout as before)
        witness[23] = F::zero(); witness[24] = F::zero(); witness[25] = F::zero(); witness[26] = F::zero();
        for i in 0..4 { witness[27 + i] = diff_vals[0][i]; }
        for i in 0..4 { witness[31 + i] = term_vals[0][i]; }
        for i in 0..4 { for k in 0..4 { witness[35 + i*4 + k] = alpha_pow_vals[0][i] * diff_vals[0][k]; } }
        for i in 0..4 { witness[51 + i] = term_vals[0][i]; }
        for i in 0..4 { witness[55 + i] = diff_vals[1][i]; }
        for i in 0..4 { witness[59 + i] = term_vals[1][i]; }
        for i in 0..4 { for k in 0..4 { witness[63 + i*4 + k] = alpha_pow_vals[1][i] * diff_vals[1][k]; } }
        for i in 0..4 { witness[79 + i] = expected_acc[i]; }
        
        // Sanity: correct witness should pass
        assert!(r1cs.is_satisfied(&witness), "Correct witness should pass");
        
        // Now corrupt the accumulator
        witness[acc_idx[0]] = F::from_canonical_u64(999);
        
        assert!(!r1cs.is_satisfied(&witness), "Wrong accumulator should fail BatchFRI");
        
        // Also test: wrong sign in diff (p_at_x - p_at_z instead of p_at_z - p_at_x)
        // Reset acc to expected
        witness[acc_idx[0]] = expected_acc[0];
        
        // Corrupt diff[0] to have wrong sign: diff = from_base(p_at_x) - p_at_z
        let wrong_diff_0 = ext_sub(from_base(p_at_x_vals[0]), p_at_z_vals[0]);
        for i in 0..4 { witness[27 + i] = wrong_diff_0[i]; }
        let wrong_term_0 = ext_mul(alpha_pow_vals[0], wrong_diff_0);
        for i in 0..4 { witness[31 + i] = wrong_term_0[i]; }
        for i in 0..4 { for k in 0..4 { witness[35 + i*4 + k] = alpha_pow_vals[0][i] * wrong_diff_0[k]; } }
        for i in 0..4 { witness[51 + i] = wrong_term_0[i]; }
        
        assert!(!r1cs.is_satisfied(&witness), "Wrong sign diff (p_at_x - p_at_z) should fail");
        
        println!("BatchFRI rejection tests passed: wrong acc and wrong sign both fail");
    }

    #[test]
    fn test_r1cs_compile_representative_ops() {
        // Integration test: compile a sequence of representative verifier ops to R1CS
        // and verify compilation succeeds + digest is deterministic.
        //
        // We directly construct DslIr instructions to avoid Builder complexity.
        
        use crate::circuit::AsmConfig;
        use crate::ir::{DslIr, Felt, Ext};
        use crate::r1cs::R1CSCompiler;
        use p3_field::extension::BinomialExtensionField;
        
        type TestF = BabyBear;
        type TestEF = BinomialExtensionField<BabyBear, 4>;
        type TestConfig = AsmConfig<TestF, TestEF>;
        
        // Build ops twice to verify determinism
        let build_ops = || -> Vec<DslIr<TestConfig>> {
            use p3_field::extension::BinomialExtensionField;
            
            let mut ops = Vec::new();
            
            // Create symbolic variables with null handles (only idx matters for compiler)
            let a = Felt::<TestF>::new(1, std::ptr::null_mut());
            let b = Felt::<TestF>::new(2, std::ptr::null_mut());
            let c = Felt::<TestF>::new(3, std::ptr::null_mut());
            let d = Felt::<TestF>::new(4, std::ptr::null_mut());
            let e = Felt::<TestF>::new(5, std::ptr::null_mut());
            let f = Felt::<TestF>::new(6, std::ptr::null_mut());
            let g = Felt::<TestF>::new(7, std::ptr::null_mut());
            
            // Initialize inputs with ImmF (allocates the variables)
            ops.push(DslIr::ImmF(a, F::from_canonical_u64(1)));
            ops.push(DslIr::ImmF(b, F::from_canonical_u64(2)));
            ops.push(DslIr::ImmF(c, F::from_canonical_u64(3)));
            
            // Basic felt arithmetic: d = a + b
            ops.push(DslIr::AddF(d, a, b));
            
            // e = a * b
            ops.push(DslIr::MulF(e, a, b));
            
            // f = a - c
            ops.push(DslIr::SubF(f, a, c));
            
            // g = d + f
            ops.push(DslIr::AddF(g, d, f));
            
            // Extension arithmetic
            let x = Ext::<TestF, TestEF>::new(10, std::ptr::null_mut());
            let y = Ext::<TestF, TestEF>::new(11, std::ptr::null_mut());
            let z = Ext::<TestF, TestEF>::new(12, std::ptr::null_mut());
            let w = Ext::<TestF, TestEF>::new(13, std::ptr::null_mut());
            
            // Initialize extension inputs
            let one_ext = BinomialExtensionField::<TestF, 4>::one();
            ops.push(DslIr::ImmE(x, one_ext));
            ops.push(DslIr::ImmE(y, one_ext));
            
            // z = x + y
            ops.push(DslIr::AddE(z, x, y));
            
            // w = x * y
            ops.push(DslIr::MulE(w, x, y));
            
            // Assert felt equality: a == b (will fail at runtime, but constraint is valid)
            ops.push(DslIr::AssertEqF(a, b));
            
            ops
        };
        
        let ops1 = build_ops();
        let ops2 = build_ops();
        
        // Compile both using the static compile method
        let r1cs1 = R1CSCompiler::<TestConfig>::compile(ops1);
        let r1cs2 = R1CSCompiler::<TestConfig>::compile(ops2);
        
        // Verify non-trivial R1CS was generated
        assert!(r1cs1.num_constraints > 0, "Should have generated constraints");
        assert!(r1cs1.num_vars > 5, "Should have allocated variables");
        
        // Verify determinism
        assert_eq!(r1cs1.num_vars, r1cs2.num_vars, "Variable count should be deterministic");
        assert_eq!(r1cs1.num_constraints, r1cs2.num_constraints, "Constraint count should be deterministic");
        assert_eq!(r1cs1.digest(), r1cs2.digest(), "R1CS digest should be deterministic");
        
        println!("Integration test passed:");
        println!("  - Variables: {}", r1cs1.num_vars);
        println!("  - Constraints: {}", r1cs1.num_constraints);
        println!("  - Digest: {:?}", &r1cs1.digest()[..8]);
    }

    /// Test R1CS serialization roundtrip with v2 format
    #[test]
    fn test_r1cs_serialization_roundtrip() {
        // Build a simple R1CS
        let mut r1cs = R1CS::<F>::new();
        r1cs.num_vars = 10;
        r1cs.num_public = 2;
        
        // Add some constraints
        let mut a = SparseRow::new();
        a.add_term(1, F::from_canonical_u64(3));
        a.add_term(2, F::from_canonical_u64(5));
        
        let b = SparseRow::single(3);
        
        let mut c = SparseRow::new();
        c.add_term(4, F::from_canonical_u64(7));
        c.add_term(0, F::from_canonical_u64(11)); // constant
        
        r1cs.add_constraint(a, b, c);
        
        // Add another constraint
        r1cs.add_constraint(
            SparseRow::single(5),
            SparseRow::single(6),
            SparseRow::single(7),
        );
        
        // Serialize
        let bytes = r1cs.to_bytes();
        println!("Serialized R1CS: {} bytes (header: 72, body: {})", bytes.len(), bytes.len() - 72);
        
        // Test header reading (fast path)
        let (digest, num_vars, num_constraints, num_public, total_nonzeros) = 
            R1CS::<F>::read_header(&bytes).expect("Failed to read header");
        println!("Header: vars={}, constraints={}, public={}, nonzeros={}", 
            num_vars, num_constraints, num_public, total_nonzeros);
        println!("Digest: {:02x?}...", &digest[..8]);
        
        assert_eq!(num_vars, r1cs.num_vars);
        assert_eq!(num_constraints, r1cs.num_constraints);
        assert_eq!(num_public, r1cs.num_public);
        assert_eq!(digest, r1cs.digest());
        
        // Full deserialize with integrity verification
        let r1cs2 = R1CS::<F>::from_bytes(&bytes).expect("Failed to deserialize");
        
        // Verify structure matches
        assert_eq!(r1cs.num_vars, r1cs2.num_vars);
        assert_eq!(r1cs.num_constraints, r1cs2.num_constraints);
        assert_eq!(r1cs.num_public, r1cs2.num_public);
        assert_eq!(r1cs.a.len(), r1cs2.a.len());
        assert_eq!(r1cs.b.len(), r1cs2.b.len());
        assert_eq!(r1cs.c.len(), r1cs2.c.len());
        
        // Verify digest matches (comprehensive check)
        assert_eq!(r1cs.digest(), r1cs2.digest(), "Digest should match after roundtrip");
        
        println!("Serialization roundtrip test passed ✓");
    }
    
    /// Test that corrupted R1CS files are detected
    #[test]
    fn test_r1cs_corruption_detection() {
        let mut r1cs = R1CS::<F>::new();
        r1cs.num_vars = 5;
        r1cs.add_constraint(
            SparseRow::single(1),
            SparseRow::single(2),
            SparseRow::single(3),
        );
        
        let mut bytes = r1cs.to_bytes();
        
        // Corrupt a byte in the matrix data
        let corrupt_pos = 80; // In the body, after header
        bytes[corrupt_pos] ^= 0xFF;
        
        // Should fail integrity check
        let result = R1CS::<F>::from_bytes(&bytes);
        assert!(result.is_err(), "Corrupted R1CS should fail to load");
        assert!(result.unwrap_err().contains("digest mismatch"));
        
        println!("Corruption detection test passed ✓");
    }
}
