#include <cuda/atomic>
#include "challenger/challenger.cuh"
#include "poseidon2/poseidon2_kb31_16.cuh"
#include "poseidon2/poseidon2.cuh"
#include "fields/kb31_t.cuh"
#include "fields/kb31_extension_t.cuh"


// `found_flag` must be zeroed by the HOST before launch. Resetting it here (per thread)
// races on multi-wave grids: blocks that launch after a witness is found clear the flag,
// which disables the early exit and degrades the grind into a near-exhaustive search.
__global__ void
grindKernel(DuplexChallenger challenger, kb31_t* result, size_t bits, size_t n, bool* found_flag) {
    challenger.grind(bits, result, found_flag, n);
}

extern "C" void* grind_koala_bear() { return (void*)grindKernel; }

__global__ void
grindMultiFieldKernel(MultiField32Challenger challenger, kb31_t* result, size_t bits, size_t n, bool* found_flag) {
    challenger.grind(bits, result, found_flag, n);
}

extern "C" void* grind_multi_field32() { return (void*)grindMultiFieldKernel; }