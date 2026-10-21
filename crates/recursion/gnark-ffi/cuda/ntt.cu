#include <cuda_runtime.h>

#include "api.h"
#include "field.cuh"
#include "util.cuh"

namespace {

// In-place bit-reversal permutation, scaling every element when scale is set.
__global__ void k_bitrev(Fr* d, uint32_t log_n, Fr scale, bool do_scale) {
  uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  if (i >> log_n) return;
  uint64_t j = __brev((uint32_t)i) >> (32 - log_n);
  if (i > j) return;
  Fr a = d[i], b = d[j];
  if (do_scale) {
    a = a * scale;
    b = b * scale;
  }
  d[i] = b;
  d[j] = a;
}

// One radix-2^r pass of an iterative DIT NTT over bit-reversed input, covering stages [s0, s0 + r).
// A block owns the 2^r elements t*2^s0 + low of 2^c consecutive values of low. Element t is first
// twisted by w_{2^(s0+r)}^(low * bitrev(t)), after which the stages only need 2^r-th roots of unity.
__global__ void k_ntt_pass(Fr* d, uint32_t log_n, uint32_t s0, uint32_t r, uint32_t c, const Fr* tab) {
  extern __shared__ Fr sh[];
  Fr* roots = sh + (1u << (r + c));
  const uint32_t lanes = 1u << c;
  const uint32_t size = 1u << r;
  const uint64_t blocks_per_high = 1ull << (s0 - c);
  const uint64_t high = blockIdx.x / blocks_per_high;
  const uint64_t low0 = (blockIdx.x % blocks_per_high) << c;
  const uint64_t base = high << (s0 + r);

  // roots[k] = w_{2^r}^k for k < 2^(r-1).
  for (uint32_t k = threadIdx.x; k < size / 2; k += blockDim.x) roots[k] = pow_tab(tab, (uint64_t)k << (log_n - r));

  for (uint32_t e = threadIdx.x; e < (size << c); e += blockDim.x) {
    uint32_t lc = e & (lanes - 1), t = e >> c;
    uint64_t low = low0 + lc;
    Fr x = d[base + ((uint64_t)t << s0) + low];
    if (s0 > 0) {
      uint64_t tr = __brev(t) >> (32 - r);
      uint64_t ex = ((low * tr) & ((1ull << (s0 + r)) - 1)) << (log_n - s0 - r);
      x = x * pow_tab(tab, ex);
    }
    sh[e] = x;
  }
  __syncthreads();

  for (uint32_t j = 0; j < r; j++) {
    for (uint32_t e = threadIdx.x; e < (size << c) / 2; e += blockDim.x) {
      uint32_t lc = e & (lanes - 1), b = e >> c;
      uint32_t pos = b & ((1u << j) - 1);
      uint32_t i0 = ((b >> j) << (j + 1)) + pos, i1 = i0 + (1u << j);
      Fr u = sh[(i0 << c) + lc];
      Fr v = sh[(i1 << c) + lc] * roots[pos << (r - j - 1)];
      sh[(i0 << c) + lc] = u + v;
      sh[(i1 << c) + lc] = u - v;
    }
    __syncthreads();
  }

  for (uint32_t e = threadIdx.x; e < (size << c); e += blockDim.x) {
    uint32_t lc = e & (lanes - 1), t = e >> c;
    d[base + ((uint64_t)t << s0) + low0 + lc] = sh[e];
  }
}

constexpr uint32_t MAX_RADIX = 9;
constexpr uint32_t LANES = 2;

}  // namespace

extern "C" int sp1_ntt(void* data, uint32_t log_n, const void* tab, const sp1_fr* scale, void* stream) {
  cudaStream_t s = st(stream);
  Fr* d = reinterpret_cast<Fr*>(data);
  uint64_t n = 1ull << log_n;
  Fr sc = scale ? cst<Fr>(scale) : Fr::one();
  k_bitrev<<<blocks(n), THREADS, 0, s>>>(d, log_n, sc, scale != nullptr);
  // The first pass has unit stride and needs no lanes; later passes use MAX_RADIX - 1 to fit the lanes
  // in shared memory.
  uint32_t passes = log_n <= MAX_RADIX ? 1 : 1 + (log_n - MAX_RADIX + MAX_RADIX - 2) / (MAX_RADIX - 1);
  uint32_t s0 = 0;
  for (uint32_t p = 0; p < passes; p++) {
    uint32_t left = passes - p;
    uint32_t r = p == 0 ? log_n - (passes - 1) * (MAX_RADIX - 1) : (log_n - s0 + left - 1) / left;
    if (p == 0 && passes > 1 && r < (log_n + passes - 1) / passes) r = (log_n + passes - 1) / passes;
    if (r > MAX_RADIX - (p > 0)) r = MAX_RADIX - (p > 0);
    uint32_t c = s0 < LANES ? s0 : LANES;
    uint32_t threads = (1u << (r + c)) / 2;
    if (threads > 512) threads = 512;
    size_t shmem = ((1u << (r + c)) + (1u << r) / 2) * sizeof(Fr);
    uint64_t nblocks = n >> (r + c);
    k_ntt_pass<<<(unsigned)nblocks, threads, shmem, s>>>(d, log_n, s0, r, c, reinterpret_cast<const Fr*>(tab));
    s0 += r;
  }
  return err();
}

extern "C" int sp1_bitrev(void* data, uint32_t log_n, void* stream) {
  k_bitrev<<<blocks(1ull << log_n), THREADS, 0, st(stream)>>>(reinterpret_cast<Fr*>(data), log_n, Fr::one(), false);
  return err();
}
