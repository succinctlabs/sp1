#pragma once

#include "config.cuh"

/// Atomically add a field element `val` to `*addr` with modular reduction.
///
/// Uses a CAS loop to perform (old + val) mod `mod_val` atomically.
/// Since only thread 0 of each block writes and there are few target
/// addresses (K=3 for LogUp-GKR), contention is low and the loop
/// typically converges in 1-2 iterations.
__device__ __forceinline__ void atomicAddMod(uint32_t* addr, uint32_t val, uint32_t mod_val) {
    uint32_t old = *addr, assumed, sum;
    do {
        assumed = old;
        sum = assumed + val;
        if (sum >= mod_val) sum -= mod_val;
        old = atomicCAS(addr, assumed, sum);
    } while (old != assumed);
}

/// Atomically add an extension field element `val` to `*addr`.
///
/// Performs component-wise modular atomic addition over the 4 base-field
/// components of the extension field element.
__device__ __forceinline__ void atomicAddExt(ext_t* addr, ext_t val) {
    static constexpr uint32_t MOD = 0x7f000001u;
#pragma unroll
    for (int j = 0; j < ext_t::D; j++) {
        atomicAddMod(&addr->value[j].val, val.value[j].val, MOD);
    }
}
