#ifndef __HIPCC__
#include <cuda/atomic>
#endif
#include "challenger/challenger.cuh"
#include "poseidon2/poseidon2_kb31_16.cuh"
#include "poseidon2/poseidon2.cuh"
#include "fields/kb31_t.cuh"
#include "fields/kb31_extension_t.cuh"


__global__ __launch_bounds__(256, 1) void
grindKernel(DuplexChallenger challenger, kb31_t* result, size_t bits, size_t n, bool* found_flag) {
    // found_flag is initialized to false by the host before launch.
    // Do NOT set it here — late-starting blocks would overwrite true→false,
    // causing the search to miss early successes and run far too long.
    challenger.grind(bits, result, found_flag, n);
}

extern "C" void* grind_koala_bear() { return (void*)grindKernel; }