#include <cuda/atomic>
#include "challenger/challenger.cuh"
#include "poseidon2/poseidon2_kb31_16.cuh"
#include "poseidon2/poseidon2.cuh"
#include "fields/kb31_t.cuh"
#include "fields/kb31_extension_t.cuh"


__global__ void
grindKernel(DuplexChallenger challenger, kb31_t* result, size_t bits, size_t n, bool* found_flag) {
    found_flag[0] = false;
    challenger.grind(bits, result, found_flag, n);
}

extern "C" void* grind_koala_bear() { return (void*)grindKernel; }