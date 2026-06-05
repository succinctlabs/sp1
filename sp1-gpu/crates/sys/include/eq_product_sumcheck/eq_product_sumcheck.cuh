#pragma once

// Round-message kernels for the eq-prefixed degree-(K+1) product sumcheck (K = 64).
//
// Computes the kernel evals of h_r(t) at t in {0, 2, 3, ..., K} for each round.  The host
// recovers h_r(1) from the round claim, applies the cached Lagrange-to-power matrix to get
// h_r in power form, then multiplies by the linear eq factor to produce g_r.

// Round-r sum-as-poly (no fold).  Two variants by MLE element type.
extern "C" void* eq_product_sum_as_poly_base_64_coop_kernel();
extern "C" void* eq_product_sum_as_poly_ext_64_coop_kernel();

// Eq-prefix transition: new_eq[i] = scalar * (old_eq[2*i] + old_eq[2*i+1]).  The scalar is
// eq(zeta_r, alpha_r), absorbed into the prefix so the next round's prover message naturally
// includes the cumulative C_r factor without separate tracking.
extern "C" void* eq_prefix_fold_kernel();

// Fused round-r prover step: fold MLE by alpha, fold eq prefix (sum-pair + scale), and
// compute the next round's sum-as-poly in one global-memory pass.  Two variants by MLE
// element type (base for round-1 transition; ext for rounds 2..n-1).
extern "C" void* eq_product_fix_and_sum_base_64_coop_kernel();
extern "C" void* eq_product_fix_and_sum_ext_64_coop_kernel();
