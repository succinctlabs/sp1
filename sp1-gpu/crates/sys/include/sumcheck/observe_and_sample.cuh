#pragma once

#include "config.cuh"
#include "challenger/challenger.cuh"

/// GPU-side Fiat-Shamir observe-and-sample for the main sumcheck loops.
///
/// This kernel runs on a single thread (grid=1, block=1). It:
///   1. Reads the reduced evaluation values from a device buffer (eval_zero, eval_half)
///   2. Computes eval_one = claim - eval_zero
///   3. Normalizes eval_half (divides by 4 for quadratic)
///   4. Interpolates the univariate polynomial (degree 2)
///   5. Calls challenger.observe_ext() on each coefficient
///   6. Calls challenger.sample_ext() to get alpha
///   7. Evaluates p(alpha) to get next_claim
///   8. Writes alpha and next_claim to device buffers
///
/// Template Parameters:
///   F  - base field type (e.g. kb31_t)
///   EF - extension field type (e.g. kb31_extension_t)
///   Challenger - challenger type (DuplexChallenger or MultiField32Challenger)

/// Lagrange interpolation through 3 points to get degree-2 polynomial coefficients.
/// Given points (x0, y0), (x1, y1), (x2, y2), computes coefficients [c0, c1, c2]
/// such that p(x) = c0 + c1*x + c2*x^2.
///
/// This is the same interpolateQuadratic from branching_program.cu.
template <typename F, typename EF>
__device__ void interpolateQuadraticSumcheck(
    F x_0,
    F x_1,
    F x_2,
    EF y_0,
    EF y_1,
    EF y_2,
    EF coefficients[3]) {

    // Compute Lagrange basis denominators
    F x0102 = (x_0 - x_1) * (x_0 - x_2);
    F x1012 = (x_1 - x_0) * (x_1 - x_2);
    F x2021 = (x_2 - x_0) * (x_2 - x_1);
    F x0102x1012 = x0102 * x1012;
    F denom = x0102x1012 * x2021;
    F inv = denom.reciprocal();

    // Lagrange coefficients
    EF coeff_0 = y_0 * inv * x1012 * x2021;
    EF coeff_1 = y_1 * inv * x0102 * x2021;
    EF coeff_2 = y_2 * inv * x0102x1012;

    // Convert from Lagrange form to monomial form: p(x) = c0 + c1*x + c2*x^2
    EF c0c1 = coeff_0 + coeff_1;
    EF c0x1 = coeff_0 * x_1;
    EF c1x0 = coeff_1 * x_0;
    EF c2x0 = coeff_2 * x_0;
    EF c0c1x2 = c0c1 * x_2;

    F x0x1 = x_0 + x_1;

    // c2 = sum of Lagrange coefficients
    EF t2 = c0c1 + coeff_2;

    // c1 = -(coeff_0*(x1+x2) + coeff_1*(x0+x2) + coeff_2*(x0+x1))
    EF t1 = coeff_2 * x0x1;
    t1 += c0x1;
    t1 += c1x0;
    t1 += c0c1x2;

    // c0 = coeff_0*x1*x2 + coeff_1*x0*x2 + coeff_2*x0*x1
    EF t0 = c0x1 + c1x0;
    t0 *= x_2;
    t0 += c2x0 * x_1;

    coefficients[2] = t2;
    coefficients[1] = -t1;
    coefficients[0] = t0;
}

/// Main sumcheck observe-and-sample kernel for the quadratic (degree-2) case.
///
/// This handles the hadamard sumcheck pattern where the univariate polynomial
/// is interpolated through points at x=0, x=1, x=1/2.
///
/// The CPU-side code (hadamard.rs) does:
///   eval_one = claim - eval_zero
///   interpolate through (0, eval_zero), (1, eval_one), (1/2, eval_half * inv(4))
///
/// Parameters:
///   evals       - [in]  device buffer with [eval_zero, eval_half] (output of sum_dim reduction)
///   challenger  - [mut] the DuplexChallenger / MultiField32Challenger state on device
///   alpha_out   - [out] the sampled challenge alpha
///   claim       - [in]  the current claim value
///   next_claim  - [out] p(alpha), the evaluation of the interpolated polynomial at alpha
template <typename F, typename EF, typename Challenger>
__global__ __launch_bounds__(256) void sumcheckObserveAndSampleQuadratic(
    const EF* __restrict__ evals,
    Challenger challenger,
    EF* __restrict__ alpha_out,
    EF claim,
    EF* __restrict__ next_claim_out) {

    // Single-thread kernel
    if (blockIdx.x != 0 || threadIdx.x != 0)
        return;

    // Step 1: Read the reduced evaluations
    EF eval_zero = evals[0];
    EF eval_half_raw = evals[1];

    // Step 2: Compute eval_one = claim - eval_zero
    EF eval_one = claim - eval_zero;

    // Step 3: Normalize eval_half by dividing by 4
    // In the CPU code: eval_half * Felt::from_canonical_u16(4).inverse()
    // 4^(-1) mod p where p = 0x7f000001 = 2130706433
    F inv4 = F(4).reciprocal();
    EF eval_half = eval_half_raw * inv4;

    // Step 4: Interpolate the quadratic polynomial through
    //   (0, eval_zero), (1, eval_one), (1/2, eval_half)
    F x_0 = F::zero();
    F x_1 = F::one();
    F x_half = F::one() / F::two();

    EF coefficients[3];
    interpolateQuadraticSumcheck<F, EF>(x_0, x_1, x_half, eval_zero, eval_one, eval_half, coefficients);

    // Step 5: Observe the polynomial coefficients
    // The CPU code observes all coefficients as base field elements:
    //   coefficients.iter().flat_map(|x| x.as_base_slice()).copied()
    // Then challenger.observe_slice(&coefficients)
    // This is equivalent to observe_ext on each coefficient.
    challenger.observe_ext(&coefficients[0]);
    challenger.observe_ext(&coefficients[1]);
    challenger.observe_ext(&coefficients[2]);

    // Step 6: Sample alpha
    EF alpha = challenger.sample_ext();

    // Step 7: Write alpha
    alpha_out[0] = alpha;

    // Step 8: Evaluate p(alpha) = c0 + c1*alpha + c2*alpha^2 using Horner's method
    EF result(coefficients[2]);
    result *= alpha;
    result += coefficients[1];
    result *= alpha;
    result += coefficients[0];

    // Step 9: Write next_claim
    next_claim_out[0] = result;
}

/// Lagrange interpolation through 4 points to get degree-3 polynomial coefficients.
/// Given points (x0, y0), (x1, y1), (x2, y2), (x3, y3), computes coefficients [c0, c1, c2, c3]
/// such that p(x) = c0 + c1*x + c2*x^2 + c3*x^3.
///
/// x-coordinates are extension field elements because b_const in LogUp-GKR depends on point_last.
///
/// Uses the standard Lagrange basis approach:
///   p(x) = sum_i y_i * prod_{j!=i} (x - x_j) / (x_i - x_j)
/// then converts to monomial form via elementary symmetric polynomials.
template <typename F, typename EF>
__device__ void interpolateCubicSumcheck(
    EF x_0,
    EF x_1,
    EF x_2,
    EF x_3,
    EF y_0,
    EF y_1,
    EF y_2,
    EF y_3,
    EF coefficients[4]) {

    // Compute pairwise differences d_ij = x_i - x_j
    EF d01 = x_0 - x_1;
    EF d02 = x_0 - x_2;
    EF d03 = x_0 - x_3;
    EF d12 = x_1 - x_2;
    EF d13 = x_1 - x_3;
    EF d23 = x_2 - x_3;

    // Lagrange basis denominators: denom_i = prod_{j!=i} (x_i - x_j)
    EF denom_0 = d01 * d02 * d03;          // (x0-x1)(x0-x2)(x0-x3)
    EF denom_1 = (-d01) * d12 * d13;       // (x1-x0)(x1-x2)(x1-x3)
    EF denom_2 = (-d02) * (-d12) * d23;    // (x2-x0)(x2-x1)(x2-x3)
    EF denom_3 = (-d03) * (-d13) * (-d23); // (x3-x0)(x3-x1)(x3-x2)

    // Lagrange weights: w_i = y_i / denom_i
    EF w_0 = y_0 * denom_0.reciprocal();
    EF w_1 = y_1 * denom_1.reciprocal();
    EF w_2 = y_2 * denom_2.reciprocal();
    EF w_3 = y_3 * denom_3.reciprocal();

    // Each Lagrange basis polynomial L_i(x) = prod_{j!=i} (x - x_j) expands as:
    //   (x-a)(x-b)(x-c) = x^3 - e1*x^2 + e2*x - e3
    // where e1 = a+b+c, e2 = ab+ac+bc, e3 = abc are elementary symmetric polynomials.
    //
    // The full polynomial is p(x) = sum_i w_i * (x^3 - e1_i*x^2 + e2_i*x - e3_i), giving:
    //   c3 =  sum_i w_i
    //   c2 = -sum_i w_i * e1_i
    //   c1 =  sum_i w_i * e2_i
    //   c0 = -sum_i w_i * e3_i

    // Elementary symmetric polynomials for each basis
    // Basis 0 excludes x_0: roots are x_1, x_2, x_3
    EF e1_0 = x_1 + x_2 + x_3;
    EF e2_0 = x_1*x_2 + x_1*x_3 + x_2*x_3;
    EF e3_0 = x_1*x_2*x_3;

    // Basis 1 excludes x_1: roots are x_0, x_2, x_3
    EF e1_1 = x_0 + x_2 + x_3;
    EF e2_1 = x_0*x_2 + x_0*x_3 + x_2*x_3;
    EF e3_1 = x_0*x_2*x_3;

    // Basis 2 excludes x_2: roots are x_0, x_1, x_3
    EF e1_2 = x_0 + x_1 + x_3;
    EF e2_2 = x_0*x_1 + x_0*x_3 + x_1*x_3;
    EF e3_2 = x_0*x_1*x_3;

    // Basis 3 excludes x_3: roots are x_0, x_1, x_2
    EF e1_3 = x_0 + x_1 + x_2;
    EF e2_3 = x_0*x_1 + x_0*x_2 + x_1*x_2;
    EF e3_3 = x_0*x_1*x_2;

    // Accumulate monomial coefficients
    coefficients[3] = w_0 + w_1 + w_2 + w_3;
    coefficients[2] = -(w_0*e1_0 + w_1*e1_1 + w_2*e1_2 + w_3*e1_3);
    coefficients[1] = w_0*e2_0 + w_1*e2_1 + w_2*e2_2 + w_3*e2_3;
    coefficients[0] = -(w_0*e3_0 + w_1*e3_1 + w_2*e3_2 + w_3*e3_3);
}

/// GPU-side Fiat-Shamir observe-and-sample for the LogUp-GKR sumcheck (degree-3 / cubic case).
///
/// This kernel runs on a single thread (grid=1, block=1). It:
///   1. Reads the reduced evaluation values from device: [eval_zero, eval_half, eq_sum]
///   2. Applies eq correction: eq_correction_term = padding_adjustment - eq_sum
///   3. Adjusts: eval_zero += eq_correction_term * (1 - point_last)
///              eval_half += eq_correction_term * 4
///   4. Scales: eval_half *= 1/8
///   5. Applies eq_adjustment to both eval_zero and eval_half
///   6. Computes eval_one = claim - eval_zero
///   7. Computes b_const = (1 - point_last) / (1 - 2*point_last)
///   8. Interpolates degree-3 polynomial through:
///      (0, eval_zero), (1, eval_one), (1/2, eval_half), (b_const, 0)
///   9. Observes all 4 coefficients with the challenger
///  10. Samples alpha
///  11. Evaluates p(alpha) for next_claim
///  12. Writes alpha and next_claim to device buffers
///
/// Parameters:
///   evals              - [in]  device buffer with [eval_zero, eval_half, eq_sum] (shape [3], output of sum_dim)
///   challenger         - [mut] the DuplexChallenger / MultiField32Challenger state on device
///   alpha_out          - [out] the sampled challenge alpha
///   claim              - [in]  the current claim value
///   next_claim_out     - [out] p(alpha), the evaluation of the interpolated polynomial at alpha
///   padding_adjustment - [in]  scalar correction for padded rows
///   eq_adjustment      - [in]  scalar correction from eq polynomial
///   point_last         - [in]  the last coordinate of the current point
template <typename F, typename EF, typename Challenger>
__global__ __launch_bounds__(256) void sumcheckObserveAndSampleCubic(
    const EF* __restrict__ evals,
    Challenger challenger,
    EF* __restrict__ alpha_out,
    EF claim,
    EF* __restrict__ next_claim_out,
    EF padding_adjustment,
    EF eq_adjustment,
    EF point_last) {

    // Single-thread kernel
    if (blockIdx.x != 0 || threadIdx.x != 0)
        return;

    // Step 1: Read the reduced evaluations [eval_zero, eval_half, eq_sum]
    EF eval_zero = evals[0];
    EF eval_half = evals[1];
    EF eq_sum = evals[2];

    // Step 2: Compute eq correction term
    EF eq_correction_term = padding_adjustment - eq_sum;

    // Step 3: Apply corrections
    // eval_zero += eq_correction_term * (1 - point_last)
    EF one = EF::one();
    eval_zero += eq_correction_term * (one - point_last);
    // eval_half += eq_correction_term * 4
    EF four = EF(F(4));
    eval_half += eq_correction_term * four;

    // Step 4: Scale eval_half by 1/8
    // Since the sumcheck polynomial is homogeneous of degree 3, divide by 8 = 2^3
    EF inv8 = EF(F(8)).reciprocal();
    eval_half = eval_half * inv8;

    // Step 5: Apply eq_adjustment
    eval_zero = eval_zero * eq_adjustment;
    eval_half = eval_half * eq_adjustment;

    // Step 6: Compute eval_one = claim - eval_zero
    EF eval_one = claim - eval_zero;

    // Step 7: Compute b_const = (1 - point_last) / (1 - 2*point_last)
    EF two = EF(F(2));
    EF b_const = (one - point_last) * (one - two * point_last).reciprocal();

    // Step 8: Interpolate degree-3 polynomial through 4 points:
    //   (0, eval_zero), (1, eval_one), (1/2, eval_half), (b_const, 0)
    EF x_0 = EF::zero();
    EF x_1 = one;
    EF x_2 = two.reciprocal();  // 1/2
    EF x_3 = b_const;

    EF coefficients[4];
    interpolateCubicSumcheck<F, EF>(
        x_0, x_1, x_2, x_3,
        eval_zero, eval_one, eval_half, EF::zero(),
        coefficients);

    // Step 9: Observe the polynomial coefficients
    // The CPU code observes all coefficients as base field elements:
    //   coefficients.iter().flat_map(|x| x.as_base_slice()).copied()
    challenger.observe_ext(&coefficients[0]);
    challenger.observe_ext(&coefficients[1]);
    challenger.observe_ext(&coefficients[2]);
    challenger.observe_ext(&coefficients[3]);

    // Step 10: Sample alpha
    EF alpha = challenger.sample_ext();

    // Step 11: Write alpha
    alpha_out[0] = alpha;

    // Step 12: Evaluate p(alpha) = c0 + c1*alpha + c2*alpha^2 + c3*alpha^3 using Horner's method
    EF result(coefficients[3]);
    result *= alpha;
    result += coefficients[2];
    result *= alpha;
    result += coefficients[1];
    result *= alpha;
    result += coefficients[0];

    // Step 13: Write next_claim
    next_claim_out[0] = result;
}
