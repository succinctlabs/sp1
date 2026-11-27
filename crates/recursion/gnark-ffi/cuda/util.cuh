#pragma once

#include <cuda_runtime.h>

#include "field.cuh"

constexpr int THREADS = 256;
constexpr uint32_t TAB_LO_BITS = 12;

inline unsigned blocks(uint64_t n) { return (unsigned)((n + THREADS - 1) / THREADS); }
inline cudaStream_t st(void* s) { return reinterpret_cast<cudaStream_t>(s); }
inline int err() { return (int)cudaGetLastError(); }

template <class T, class U>
__host__ __device__ __forceinline__ T cst(const U* p) {
  return *reinterpret_cast<const T*>(p);
}

// Power tables hold c^i for i < 2^12 followed by c^(2^12 * i), in Montgomery form.
__device__ __forceinline__ Fr pow_tab(const Fr* tab, uint64_t j) {
  return tab[j & ((1u << TAB_LO_BITS) - 1)] * tab[(1u << TAB_LO_BITS) + (j >> TAB_LO_BITS)];
}

// The value at position p of the support <w> || u<w> || u^2<w> of the copy constraint permutation.
__device__ __forceinline__ Fr id_value(uint32_t p, uint64_t n, const Fr* tab_w, const Fr& u, const Fr& u2) {
  uint64_t k = p / n;
  Fr w = pow_tab(tab_w, p - k * n);
  return k == 0 ? w : w * (k == 1 ? u : u2);
}
