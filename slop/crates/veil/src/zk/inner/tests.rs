#![allow(clippy::disallowed_types, clippy::disallowed_methods)]

use std::time::Instant;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use slop_algebra::AbstractField;
use slop_challenger::IopCtx;
use slop_koala_bear::KoalaBearDegree4Duplex;

use super::prover::ZkProverContext;
use super::{
    ConstraintContextInner, ConstraintContextInnerExt, ExpressionIndex, TranscriptLinConstraint,
    ZkCnstrAndReadingCtxInner,
};
use slop_merkle_tree::Poseidon2KoalaBear16Prover;

type MK = Poseidon2KoalaBear16Prover;
use crate::name_constraint;

/// Single source of truth constraint builder.
///
/// This function is generic over the field K, element type E, and context C.
/// Both prover and verifier call this with their respective types
/// to ensure identical constraint generation.
///
/// Constraints tested:
/// - Linear: a + b = c
/// - Linear: x - y = d
/// - Multiplicative: x * y = z (element multiplication)
/// - Expression multiplication: (a + 2*b) * c = e
/// - Squaring: (a + 2*b)^2 = f
/// - Scalar multiplication: 3*a - b = g
/// - Chained products: x * y * a = h
/// - Complex expression: (a + b) * (x - y) + c = i
/// - Nested: ((a * b) + c) * d = j
/// - Nested scalar multiplication: 2 * (3*a + b) = k
/// - Chained scalar multiplication: 2*2*2*2*(a + 2b) = l
#[allow(clippy::too_many_arguments)]
fn build_constraints<K, C>(
    a: C::Expr,
    b: C::Expr,
    c: C::Expr,
    x: C::Expr,
    y: C::Expr,
    z: C::Expr,
    d: C::Expr,
    e: C::Expr,
    f: C::Expr,
    g: C::Expr,
    h: C::Expr,
    i: C::Expr,
    j: C::Expr,
    k: C::Expr,
    l: C::Expr,
) where
    K: AbstractField + Copy,
    C: ConstraintContextInnerExt<K>,
{
    let mut ctx: C = a.as_ref().clone();
    // Linear constraint: a + b = c
    let constraint_1 = a.clone() + b.clone() - c.clone();
    ctx.assert_zero(constraint_1);
    // name_constraint!(ctx, "c1: a + b = c");

    // Linear constraint: x - y = d
    let constraint_2 = x.clone() - y.clone() - d.clone();
    ctx.assert_zero(constraint_2);
    // name_constraint!(ctx, "c2: x - y = d");
    // Multiplicative constraint: x * y = z
    let constraint_3 = x.clone() * y.clone() - z;
    ctx.assert_zero(constraint_3);
    name_constraint!(ctx, "c3: x * y = z");

    // Expression with addition: a + 2b
    let a_plus_2b = a.clone() + b.clone() + b.clone();

    // Expression multiplication: (a + 2*b) * c = e
    let constraint_4 = a_plus_2b.clone() * c.clone() - e;
    ctx.assert_zero(constraint_4);
    name_constraint!(ctx, "c4: (a + 2b) * c = e");

    // Squaring: (a + 2*b)^2 = f
    let constraint_5 = a_plus_2b.clone() * a_plus_2b.clone() - f;
    ctx.assert_zero(constraint_5);
    name_constraint!(ctx, "c5: (a + 2b)^2 = f");

    // Scalar multiplication: 3*a - b = g
    let three = K::one() + K::one() + K::one();
    let constraint_6 = a.clone() * three - b.clone() - g;
    ctx.assert_zero(constraint_6);
    name_constraint!(ctx, "c6: 3*a - b = g");

    // Chained products: x * y * a = h (tests associativity)
    let xy = x.clone() * y.clone();
    let constraint_7 = xy * a.clone() - h;
    ctx.assert_zero(constraint_7);
    name_constraint!(ctx, "c7: x * y * a = h");

    // Complex expression: (a + b) * (x - y) + c = i
    let a_plus_b = a.clone() + b.clone();
    let x_minus_y = x - y;
    let constraint_8 = a_plus_b * x_minus_y + c.clone() - i;
    ctx.assert_zero(constraint_8);
    name_constraint!(ctx, "c8: (a + b) * (x - y) + c = i");

    // Nested: ((a * b) + c) * d = j
    let constraint_9 = (a.clone() * b.clone() + c) * d - j;
    ctx.assert_zero(constraint_9);
    name_constraint!(ctx, "c9: ((a * b) + c) * d = j");

    // Nested scalar multiplication: 2 * (3*a + b) = k
    let two = K::one() + K::one();
    let three_a_plus_b = a.clone() * three + b;
    let constraint_10 = three_a_plus_b * two - k;
    ctx.assert_zero(constraint_10);
    name_constraint!(ctx, "c10: 2 * (3*a + b) = k");

    // Chained scalar multiplication: 2*2*2*2*(a + 2b) = l
    let constraint_11 = a_plus_2b * two * two * two * two - l;
    ctx.assert_zero(constraint_11);
    name_constraint!(ctx, "c11: 2*2*2*2*(a + 2b) = l");
}

#[tokio::test]
async fn test_zk_builder_with_generic_constraints() {
    const MASK_LENGTH: usize = 24;
    type GC = KoalaBearDegree4Duplex;

    let mut rng = ChaCha20Rng::from_entropy();

    // Generate random test values
    let a_val: <GC as IopCtx>::EF = rng.gen();
    let b_val: <GC as IopCtx>::EF = rng.gen();
    let c_val = a_val + b_val; // c = a + b

    let x_val: <GC as IopCtx>::EF = rng.gen();
    let y_val: <GC as IopCtx>::EF = rng.gen();
    let z_val = x_val * y_val; // z = x * y
    let d_val = x_val - y_val; // d = x - y

    let a_plus_2b = a_val + b_val + b_val;
    let e_val = a_plus_2b * c_val; // e = (a + 2*b) * c
    let f_val = a_plus_2b * a_plus_2b; // f = (a + 2*b)^2

    let three = <GC as IopCtx>::EF::one() + <GC as IopCtx>::EF::one() + <GC as IopCtx>::EF::one();
    let g_val = a_val * three - b_val; // g = 3*a - b
    let h_val = x_val * y_val * a_val; // h = x * y * a
    let i_val = (a_val + b_val) * (x_val - y_val) + c_val; // i = (a + b) * (x - y) + c
    let j_val = (a_val * b_val + c_val) * d_val; // j = ((a * b) + c) * d
    let two = <GC as IopCtx>::EF::one() + <GC as IopCtx>::EF::one();
    let k_val = (a_val * three + b_val) * two; // k = 2 * (3*a + b)
    let l_val = a_plus_2b * two * two * two * two; // l = 2*2*2*2*(a + 2b)

    // Prover side
    let zkproof = {
        let mut prover_context: ZkProverContext<GC, MK> =
            ZkProverContext::initialize(MASK_LENGTH, &mut rng);

        // Add values to the transcript
        let a_elem = prover_context.add_value(a_val);
        let b_elem = prover_context.add_value(b_val);
        let c_elem = prover_context.add_value(c_val);
        let x_elem = prover_context.add_value(x_val);
        let y_elem = prover_context.add_value(y_val);
        let z_elem = prover_context.add_value(z_val);
        let d_elem = prover_context.add_value(d_val);
        let e_elem = prover_context.add_value(e_val);
        let f_elem = prover_context.add_value(f_val);
        let g_elem = prover_context.add_value(g_val);
        let h_elem = prover_context.add_value(h_val);
        let i_elem = prover_context.add_value(i_val);
        let j_elem = prover_context.add_value(j_val);
        let k_elem = prover_context.add_value(k_val);
        let l_elem = prover_context.add_value(l_val);

        // Build constraints using the single source of truth function
        build_constraints::<_, ZkProverContext<GC, MK>>(
            a_elem, b_elem, c_elem, x_elem, y_elem, z_elem, d_elem, e_elem, f_elem, g_elem, h_elem,
            i_elem, j_elem, k_elem, l_elem,
        );

        // Generate the proof
        prover_context.prove_without_pcs(&mut rng)
    };

    // Verifier side
    {
        let mut verifier_context = zkproof.open();

        // Read elements from transcript in the same order as prover
        let a_elem = verifier_context.read_one().expect("Failed to read a");
        let b_elem = verifier_context.read_one().expect("Failed to read b");
        let c_elem = verifier_context.read_one().expect("Failed to read c");
        let x_elem = verifier_context.read_one().expect("Failed to read x");
        let y_elem = verifier_context.read_one().expect("Failed to read y");
        let z_elem = verifier_context.read_one().expect("Failed to read z");
        let d_elem = verifier_context.read_one().expect("Failed to read d");
        let e_elem = verifier_context.read_one().expect("Failed to read e");
        let f_elem = verifier_context.read_one().expect("Failed to read f");
        let g_elem = verifier_context.read_one().expect("Failed to read g");
        let h_elem = verifier_context.read_one().expect("Failed to read h");
        let i_elem = verifier_context.read_one().expect("Failed to read i");
        let j_elem = verifier_context.read_one().expect("Failed to read j");
        let k_elem = verifier_context.read_one().expect("Failed to read k");
        let l_elem = verifier_context.read_one().expect("Failed to read l");

        // Build constraints using the same single source of truth function
        build_constraints::<_, crate::zk::inner::ZkVerificationContext<GC>>(
            a_elem, b_elem, c_elem, x_elem, y_elem, z_elem, d_elem, e_elem, f_elem, g_elem, h_elem,
            i_elem, j_elem, k_elem, l_elem,
        );

        // Verify the proof
        verifier_context.verify_without_pcs().expect("Proof verification failed");
    }
}

/// Constraint builder for testing equal-index optimizations.
///
/// Tests the optimization where Add(idx, idx) = 2 * expr and Sub(idx, idx) = 0.
/// Also tests reusing the same complex expression in multiple products.
///
/// Constraints tested:
/// - expr + expr = double (equal-index Add optimization)
/// - expr - expr = zero (equal-index Sub optimization)
/// - complex_expr * a = prod1, complex_expr * b = prod2 (reusing materialized expr)
/// - (a + b + c) used in multiple products
/// - nested: ((a + b) + (a + b)) * c (nested equal-index)
#[allow(clippy::too_many_arguments)]
fn build_equal_index_constraints<K, C>(
    a: C::Expr,
    b: C::Expr,
    c: C::Expr,
    double_a: C::Expr,
    zero: C::Expr,
    double_sum: C::Expr,
    prod1: C::Expr,
    prod2: C::Expr,
    prod3: C::Expr,
    nested_result: C::Expr,
) where
    K: AbstractField + Copy,
    C: ConstraintContextInnerExt<K>,
{
    let mut ctx: C = a.as_ref().clone();
    // Test 1: a + a = double_a (equal-index Add, simple element)
    let expr_a = a.clone();
    let constraint_1 = expr_a.clone() + expr_a - double_a;
    ctx.assert_zero(constraint_1);
    name_constraint!(ctx, "c1: a + a = double_a");

    // Test 2: a - a = zero (equal-index Sub, simple element)
    let expr_a2 = a.clone();
    let constraint_2 = expr_a2.clone() - expr_a2 - zero;
    ctx.assert_zero(constraint_2);
    name_constraint!(ctx, "c2: a - a = zero");

    // Test 3: Create a complex expression and add it to itself
    // (a + b + c) + (a + b + c) = double_sum
    let sum_abc = a.clone() + b.clone() + c.clone();
    let constraint_3 = sum_abc.clone() + sum_abc.clone() - double_sum;
    ctx.assert_zero(constraint_3);
    name_constraint!(ctx, "c3: (a+b+c) + (a+b+c) = double_sum");

    // Test 4: Reuse the same complex expression in multiple products
    // (a + b + c) * a = prod1
    let constraint_4 = sum_abc.clone() * a.clone() - prod1;
    ctx.assert_zero(constraint_4);
    name_constraint!(ctx, "c4: (a+b+c) * a = prod1");

    // Test 5: (a + b + c) * b = prod2 (reusing already materialized sum_abc)
    let constraint_5 = sum_abc.clone() * b.clone() - prod2;
    ctx.assert_zero(constraint_5);
    name_constraint!(ctx, "c5: (a+b+c) * b = prod2");

    // Test 6: (a + b + c) * c = prod3 (reusing already materialized sum_abc again)
    let constraint_6 = sum_abc * c.clone() - prod3;
    ctx.assert_zero(constraint_6);
    name_constraint!(ctx, "c6: (a+b+c) * c = prod3");

    // Test 7: Nested equal-index: ((a + b) + (a + b)) * c = nested_result
    // This tests that the equal-index optimization works recursively
    let a_plus_b = a.clone() + b.clone();
    let doubled_a_plus_b = a_plus_b.clone() + a_plus_b; // equal-index Add on a complex expr
    let constraint_7 = doubled_a_plus_b * c - nested_result;
    ctx.assert_zero(constraint_7);
    name_constraint!(ctx, "c7: ((a+b) + (a+b)) * c = nested_result");
}

#[tokio::test]
async fn test_equal_index_optimization() {
    const MASK_LENGTH: usize = 14;
    type GC = KoalaBearDegree4Duplex;

    let mut rng = ChaCha20Rng::from_entropy();

    // Generate random test values
    let a_val: <GC as IopCtx>::EF = rng.gen();
    let b_val: <GC as IopCtx>::EF = rng.gen();
    let c_val: <GC as IopCtx>::EF = rng.gen();

    // Computed values
    let two = <GC as IopCtx>::EF::one() + <GC as IopCtx>::EF::one();
    let double_a_val = a_val * two; // a + a
    let zero_val = <GC as IopCtx>::EF::zero(); // a - a
    let sum_abc = a_val + b_val + c_val;
    let double_sum_val = sum_abc * two; // (a+b+c) + (a+b+c)
    let prod1_val = sum_abc * a_val; // (a+b+c) * a
    let prod2_val = sum_abc * b_val; // (a+b+c) * b
    let prod3_val = sum_abc * c_val; // (a+b+c) * c
    let nested_result_val = (a_val + b_val) * two * c_val; // ((a+b) + (a+b)) * c

    // Prover side
    let zkproof = {
        let mut prover_context: ZkProverContext<GC, MK> =
            ZkProverContext::initialize(MASK_LENGTH, &mut rng);

        // Add values to the transcript
        let a_elem = prover_context.add_value(a_val);
        let b_elem = prover_context.add_value(b_val);
        let c_elem = prover_context.add_value(c_val);
        let double_a_elem = prover_context.add_value(double_a_val);
        let zero_elem = prover_context.add_value(zero_val);
        let double_sum_elem = prover_context.add_value(double_sum_val);
        let prod1_elem = prover_context.add_value(prod1_val);
        let prod2_elem = prover_context.add_value(prod2_val);
        let prod3_elem = prover_context.add_value(prod3_val);
        let nested_result_elem = prover_context.add_value(nested_result_val);

        // Build constraints
        build_equal_index_constraints::<_, ZkProverContext<GC, MK>>(
            a_elem,
            b_elem,
            c_elem,
            double_a_elem,
            zero_elem,
            double_sum_elem,
            prod1_elem,
            prod2_elem,
            prod3_elem,
            nested_result_elem,
        );

        // Generate the proof
        prover_context.prove_without_pcs(&mut rng)
    };

    // Verifier side
    {
        let mut verifier_context = zkproof.open();

        // Read elements from transcript in the same order as prover
        let a_elem = verifier_context.read_one().expect("Failed to read a");
        let b_elem = verifier_context.read_one().expect("Failed to read b");
        let c_elem = verifier_context.read_one().expect("Failed to read c");
        let double_a_elem = verifier_context.read_one().expect("Failed to read double_a");
        let zero_elem = verifier_context.read_one().expect("Failed to read zero");
        let double_sum_elem = verifier_context.read_one().expect("Failed to read double_sum");
        let prod1_elem = verifier_context.read_one().expect("Failed to read prod1");
        let prod2_elem = verifier_context.read_one().expect("Failed to read prod2");
        let prod3_elem = verifier_context.read_one().expect("Failed to read prod3");
        let nested_result_elem = verifier_context.read_one().expect("Failed to read nested_result");

        // Build constraints using the same function
        build_equal_index_constraints::<_, crate::zk::inner::ZkVerificationContext<GC>>(
            a_elem,
            b_elem,
            c_elem,
            double_a_elem,
            zero_elem,
            double_sum_elem,
            prod1_elem,
            prod2_elem,
            prod3_elem,
            nested_result_elem,
        );

        // Verify the proof
        verifier_context.verify_without_pcs().expect("Proof verification failed");
    }
}

/// Computes the dot product constraint using TranscriptLinConstraint arithmetic.
///
/// This approach converts ExpressionIndex elements to TranscriptIndex immediately
/// and builds up the constraint using TranscriptLinConstraint arithmetic with
/// scalar multiplication by the public coefficients.
fn build_dot_product_constraint_transcript<K, C>(
    private_vec: Vec<ExpressionIndex<K, C>>,
    public_coeffs: &[K],
    result: ExpressionIndex<K, C>,
) where
    K: AbstractField + Copy + Eq,
    C: ConstraintContextInner<K> + super::constraints::private::Sealed,
{
    let mut ctx: C = private_vec[0].as_ref().clone();

    assert_eq!(private_vec.len(), public_coeffs.len(), "Vectors must have the same length");

    // Convert each element to TranscriptIndex, scale by public coefficient, and accumulate
    let dot_constraint: TranscriptLinConstraint<K> = private_vec
        .iter()
        .zip(public_coeffs.iter())
        .fold(TranscriptLinConstraint::default(), |acc, (elem, &coeff)| {
            let idx = elem.clone().try_into_index().expect("element must be materialized");
            // Scale the index by the public coefficient and add to accumulator
            acc + idx * coeff
        });

    // Subtract the result
    let result_idx = result.try_into_index().expect("result must be a materialized element");
    let final_constraint = dot_constraint - result_idx;

    // Add the constraint to the context
    ctx.add_lin_constraint(final_constraint);
    name_constraint!(ctx, "dot product constraint (transcript)");
}

/// Computes the dot product constraint using ExpressionIndex arithmetic.
///
/// This approach keeps everything as ExpressionIndex and uses scalar multiplication
/// with the public coefficients, building up the expression tree.
fn build_dot_product_constraint_expression_index<K, C>(
    private_vec: Vec<ExpressionIndex<K, C>>,
    public_coeffs: &[K],
    result: ExpressionIndex<K, C>,
) where
    K: AbstractField + Copy,
    C: ConstraintContextInner<K> + super::constraints::private::Sealed,
{
    assert_eq!(private_vec.len(), public_coeffs.len(), "Vectors must have the same length");

    let mut ctx: C = private_vec[0].as_ref().clone();

    // Build up the dot product using ExpressionIndex arithmetic
    let mut iter = private_vec.iter().zip(public_coeffs.iter());
    let (first_elem, &first_coeff) = iter.next().expect("Vectors must be non-empty");
    let first_term = first_elem.clone() * first_coeff;

    let dot_sum = iter.fold(first_term, |acc, (elem, &coeff)| {
        let term = elem.clone() * coeff;
        acc + term
    });

    // Create the constraint: dot_sum - result = 0
    let constraint = dot_sum - result;
    ctx.assert_zero_inner(constraint);
    name_constraint!(ctx, "dot product constraint (expression index)");
}

/// Test comparing constraint generation performance for dot product.
///
/// Generates a random private vector of length LENGTH and a random public coefficient
/// vector, computes their dot product, and measures the time taken for constraint
/// generation using two approaches:
/// 1. TranscriptLinConstraint arithmetic (convert indices early)
/// 2. ExpressionIndex arithmetic (lazy conversion via assert_zero)
#[tokio::test]
async fn test_dot_product_constraint_generation_comparison() {
    const LENGTH: usize = 10000;
    const MASK_LENGTH: usize = LENGTH + 1; // private_vec + result
    type GC = KoalaBearDegree4Duplex;

    let mut rng = ChaCha20Rng::from_entropy();

    // Generate random private vector (in transcript)
    let private_vec_vals: Vec<<GC as IopCtx>::EF> =
        std::iter::repeat_with(|| rng.gen()).take(LENGTH).collect();

    // Generate random public coefficients (known to both prover and verifier)
    let public_coeffs: Vec<<GC as IopCtx>::EF> =
        std::iter::repeat_with(|| rng.gen()).take(LENGTH).collect();

    // Compute the dot product
    let dot_product_val: <GC as IopCtx>::EF =
        private_vec_vals.iter().zip(public_coeffs.iter()).map(|(a, b)| *a * *b).sum();

    eprintln!("\n========== Dot Product Constraint Generation Comparison ==========");
    eprintln!("Vector length: {}", LENGTH);
    eprintln!();

    // =========================================================================
    // Test 1: TranscriptLinConstraint approach
    // =========================================================================
    eprintln!("--- TranscriptLinConstraint Approach ---");
    let prover_start = Instant::now();
    let zkproof_transcript = {
        let mut prover_context: ZkProverContext<GC, MK> =
            ZkProverContext::initialize_only_lin_constraints(MASK_LENGTH, &mut rng);

        // Add private vector to transcript
        let private_vec_elems: Vec<_> =
            private_vec_vals.iter().map(|&v| prover_context.add_value(v)).collect();
        let result_elem = prover_context.add_value(dot_product_val);

        build_dot_product_constraint_transcript(private_vec_elems, &public_coeffs, result_elem);

        prover_context.prove_without_pcs(&mut rng)
    };
    let prover_duration = prover_start.elapsed();
    eprintln!("  Prover time: {:?}", prover_duration);

    // Verify the transcript approach proof
    let verifier_start = Instant::now();
    {
        let mut verifier_context = zkproof_transcript.open();

        let private_vec_elems: Vec<_> = (0..LENGTH)
            .map(|_| verifier_context.read_one().expect("Failed to read private_vec element"))
            .collect();
        let result_elem = verifier_context.read_one().expect("Failed to read result");

        build_dot_product_constraint_transcript(private_vec_elems, &public_coeffs, result_elem);

        verifier_context
            .verify_without_pcs()
            .expect("Transcript approach proof verification failed");
    }
    let verifier_duration = verifier_start.elapsed();
    eprintln!("  Verifier time: {:?}", verifier_duration);

    // =========================================================================
    // Test 2: ExpressionIndex approach
    // =========================================================================
    eprintln!();
    eprintln!("--- ExpressionIndex Approach ---");
    let prover_start = Instant::now();
    let zkproof_expr_index = {
        let mut prover_context: ZkProverContext<GC, MK> =
            ZkProverContext::initialize_only_lin_constraints(MASK_LENGTH, &mut rng);

        // Add private vector to transcript
        let private_vec_elems: Vec<_> =
            private_vec_vals.iter().map(|&v| prover_context.add_value(v)).collect();
        let result_elem = prover_context.add_value(dot_product_val);

        build_dot_product_constraint_expression_index(
            private_vec_elems,
            &public_coeffs,
            result_elem,
        );

        prover_context.prove_without_pcs(&mut rng)
    };
    let prover_duration = prover_start.elapsed();
    eprintln!("  Prover time: {:?}", prover_duration);

    // Verify the expression index approach proof
    let verifier_start = Instant::now();
    {
        let mut verifier_context = zkproof_expr_index.open();

        let private_vec_elems: Vec<_> = (0..LENGTH)
            .map(|_| verifier_context.read_one().expect("Failed to read private_vec element"))
            .collect();
        let result_elem = verifier_context.read_one().expect("Failed to read result");

        build_dot_product_constraint_expression_index(
            private_vec_elems,
            &public_coeffs,
            result_elem,
        );

        verifier_context
            .verify_without_pcs()
            .expect("ExpressionIndex approach proof verification failed");
    }
    let verifier_duration = verifier_start.elapsed();
    eprintln!("  Verifier time: {:?}", verifier_duration);

    eprintln!();
    eprintln!("Both approaches verified successfully!");
    eprintln!("==================================================================\n");
}

/// Test that PCS commitment tracking works correctly.
///
/// This tests the infrastructure for registering PCS commitments,
/// without actually performing PCS proofs (to avoid circular dependencies).
/// Eval claims are tested separately as they require a PCS prover.
#[test]
fn test_pcs_commitment_tracking() {
    use super::MleCommitmentIndex;

    type GC = KoalaBearDegree4Duplex;
    let mut rng = ChaCha20Rng::from_entropy();

    eprintln!("\n==================================================================");
    eprintln!("PCS Commitment Tracking Test");
    eprintln!("==================================================================\n");

    // Generate random commitment digests (simulating PCS commits)
    let digest1: <GC as IopCtx>::Digest = rng.gen();
    let digest2: <GC as IopCtx>::Digest = rng.gen();

    // Test prover side
    let zkproof = {
        let masks_length = 2;
        let mut prover_context: ZkProverContext<GC, MK> =
            ZkProverContext::initialize_only_lin_constraints(masks_length, &mut rng);

        // Register commitments (passing () for prover_data since we don't need it in this test)
        let commit_idx1 = prover_context.register_commitment(digest1, (), 10, 4);
        let commit_idx2 = prover_context.register_commitment(digest2, (), 12, 6);

        assert_eq!(commit_idx1, MleCommitmentIndex::new(0));
        assert_eq!(commit_idx2, MleCommitmentIndex::new(1));

        // Verify we tracked the commitments
        let commitments = prover_context.pcs_commitments();
        assert_eq!(commitments.len(), 2);
        assert_eq!(commitments[0].num_vars, 10);
        assert_eq!(commitments[0].log_num_polys, 4);
        assert_eq!(commitments[1].num_vars, 12);
        assert_eq!(commitments[1].log_num_polys, 6);

        // Add some values to have something in the transcript
        let _val1 = prover_context.add_value(rng.gen());
        let _val2 = prover_context.add_value(rng.gen());

        // No eval claims, so prove_without_pcs is fine
        prover_context.prove_without_pcs(&mut rng)
    };

    // Test verifier side
    {
        let mut verifier_context = zkproof.open();

        // Read commitments (must match order and parameters)
        let commit_idx1 =
            verifier_context.read_next_pcs_commitment(10, 4).expect("Failed to read commitment 1");
        let commit_idx2 =
            verifier_context.read_next_pcs_commitment(12, 6).expect("Failed to read commitment 2");

        assert_eq!(commit_idx1, MleCommitmentIndex::new(0));
        assert_eq!(commit_idx2, MleCommitmentIndex::new(1));

        // Verify wrong parameters fail (no more commitments to read)
        assert!(verifier_context.read_next_pcs_commitment(10, 4).is_none());

        // Read values from transcript
        let _val1 = verifier_context.read_one().expect("Failed to read val 1");
        let _val2 = verifier_context.read_one().expect("Failed to read val 2");

        // Verify passes (no eval claims in this test)
        verifier_context.verify_without_pcs().expect("Verification failed");
    }

    eprintln!("PCS commitment tracking test passed!");
    eprintln!("==================================================================\n");
}
