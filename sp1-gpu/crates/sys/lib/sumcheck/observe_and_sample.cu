#include "sumcheck/observe_and_sample.cuh"

// Export kernel function pointers for the quadratic observe-and-sample kernel.
// These follow the same pattern as interpolateAndObserve_kernel_duplex/multi_field_32
// in branching_program.cu.

extern "C" void* sumcheck_observe_and_sample_quadratic_duplex() {
    return (void*)sumcheckObserveAndSampleQuadratic<kb31_t, kb31_extension_t, DuplexChallenger>;
}

extern "C" void* sumcheck_observe_and_sample_quadratic_multi_field_32() {
    return (void*)sumcheckObserveAndSampleQuadratic<kb31_t, kb31_extension_t, MultiField32Challenger>;
}

// Export kernel function pointers for the cubic observe-and-sample kernel (LogUp-GKR).
// These handle degree-3 polynomials with eq-correction and 4-point interpolation.

extern "C" void* sumcheck_observe_and_sample_cubic_duplex() {
    return (void*)sumcheckObserveAndSampleCubic<kb31_t, kb31_extension_t, DuplexChallenger>;
}

extern "C" void* sumcheck_observe_and_sample_cubic_multi_field_32() {
    return (void*)sumcheckObserveAndSampleCubic<kb31_t, kb31_extension_t, MultiField32Challenger>;
}
