#pragma once

// Round message kernels for a degree-K product sumcheck.
//
// Each kernel computes the univariate prover message of one sumcheck round
// over the LAST variable of K multilinears A_0, ..., A_{K-1}, where
// p(t) := sum_{x in {0,1}^{n-1}} prod_{j} A_j(x, t).  The kernel produces
// p evaluated at K points (t = 0, 2, 3, ..., K), partial-summed per block.
// The K+1th coefficient is recovered on the host from the round claim
// p(0) + p(1) = claim.

// Round 0 sum-as-poly (base-field input only — round 0 always operates on base MLEs).
extern "C" void* product_sumcheck_sum_as_poly_base_2_kernel();
extern "C" void* product_sumcheck_sum_as_poly_base_4_kernel();
extern "C" void* product_sumcheck_sum_as_poly_base_8_kernel();
extern "C" void* product_sumcheck_sum_as_poly_base_16_kernel();
extern "C" void* product_sumcheck_sum_as_poly_base_32_kernel();
extern "C" void* product_sumcheck_sum_as_poly_base_64_kernel();

// Simple (thread-per-x_top) fused fold-by-alpha + sum-as-poly for rounds 1..n-1.
// Used only for K ∈ {2, 4, 8}; larger K dispatches to the cooperative variant.
extern "C" void* product_sumcheck_fix_and_sum_base_2_kernel();
extern "C" void* product_sumcheck_fix_and_sum_base_4_kernel();
extern "C" void* product_sumcheck_fix_and_sum_base_8_kernel();

extern "C" void* product_sumcheck_fix_and_sum_ext_2_kernel();
extern "C" void* product_sumcheck_fix_and_sum_ext_4_kernel();
extern "C" void* product_sumcheck_fix_and_sum_ext_8_kernel();

// Cooperative (K threads per tile, TPB = 256 / K) fused fold-by-alpha + sum-as-poly.
// Used for K ∈ {16, 32, 64}, where the simple kernel hits a register cliff.
extern "C" void* product_sumcheck_fix_and_sum_coop_base_16_kernel();
extern "C" void* product_sumcheck_fix_and_sum_coop_base_32_kernel();
extern "C" void* product_sumcheck_fix_and_sum_coop_base_64_kernel();

extern "C" void* product_sumcheck_fix_and_sum_coop_ext_16_kernel();
extern "C" void* product_sumcheck_fix_and_sum_coop_ext_32_kernel();
extern "C" void* product_sumcheck_fix_and_sum_coop_ext_64_kernel();
