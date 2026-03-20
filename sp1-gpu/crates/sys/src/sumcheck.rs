use crate::runtime::KernelPtr;

extern "C" {
    pub fn hadamard_univariate_poly_eval_koala_bear_base_ext_kernel() -> KernelPtr;
    pub fn hadamard_univariate_poly_eval_koala_bear_base_kernel() -> KernelPtr;
    pub fn hadamard_univariate_poly_eval_koala_bear_ext_kernel() -> KernelPtr;

    // GPU-side Fiat-Shamir observe-and-sample kernels for the main sumcheck loops.
    // These run on a single thread and perform interpolation, challenger observe/sample,
    // and polynomial evaluation entirely on the GPU, eliminating D2H round-trips.
    pub fn sumcheck_observe_and_sample_quadratic_duplex() -> KernelPtr;
    pub fn sumcheck_observe_and_sample_quadratic_multi_field_32() -> KernelPtr;

    // GPU-side Fiat-Shamir observe-and-sample kernels for the LogUp-GKR sumcheck (degree-3).
    // These handle eq-correction, 4-point interpolation through (0, eval_zero), (1, eval_one),
    // (1/2, eval_half), (b_const, 0), and challenger observe/sample entirely on the GPU.
    pub fn sumcheck_observe_and_sample_cubic_duplex() -> KernelPtr;
    pub fn sumcheck_observe_and_sample_cubic_multi_field_32() -> KernelPtr;
}
