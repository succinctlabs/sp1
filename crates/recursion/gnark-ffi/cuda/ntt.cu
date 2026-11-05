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

__device__ __forceinline__ uint32_t rev(uint64_t i, uint32_t bits) { return __brev((uint32_t)i) >> (32 - bits); }

// The input of the first DIF pass, read from d or computed from the source.
__device__ __forceinline__ Fr load(const Fr* d, const sp1_ntt_src& s, uint64_t i, uint64_t n) {
  switch (s.kind) {
    case SP1_SRC_GATHER:
      return reinterpret_cast<const Fr*>(s.a)[reinterpret_cast<const uint32_t*>(s.b)[i]];
    case SP1_SRC_EXPAND:
      return reinterpret_cast<const Fr*>(s.a)[reinterpret_cast<const uint16_t*>(s.b)[i]];
    case SP1_SRC_SIGMA:
      return id_value(reinterpret_cast<const uint32_t*>(s.b)[i], n, reinterpret_cast<const Fr*>(s.a), cst<Fr>(&s.u),
                      cst<Fr>(&s.u2));
    default:
      return d[i];
  }
}

// One radix-2^r pass of an iterative DIT NTT over bit-reversed input, covering stages [s0, s0 + r).
// A block owns the 2^r elements t*2^s0 + low of 2^c consecutive values of low. Element t is first
// twisted by w_{2^(s0+r)}^(low * bitrev(t)), after which the stages only need 2^r-th roots of unity.
// The first pass multiplies the element at position i by coset^bitrev(i) when coset is set.
__global__ void k_dit_pass(Fr* d, uint32_t log_n, uint32_t s0, uint32_t r, uint32_t c, const Fr* tab, const Fr* coset) {
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
    uint64_t low = low0 + lc, i = base + ((uint64_t)t << s0) + low;
    Fr x = d[i];
    if (coset) x = x * pow_tab(coset, rev(i, log_n));
    if (s0 > 0) {
      uint64_t ex = ((low * rev(t, r)) & ((1ull << (s0 + r)) - 1)) << (log_n - s0 - r);
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

// One radix-2^r pass of an iterative DIF NTT over natural input, covering the r highest stages left
// once s0 have been done. In blocks of 2^(log_n - s0) elements, split as 2^r rows of M = 2^m, a block
// owns the elements t*M + low of 2^c consecutive values of low. The rows go through a 2^r-point DIF
// whose output k1 = bitrev(t) is then twisted by w_{2^(log_n - s0)}^(low * k1). The first pass reads its
// input from src and scales it when scale is set.
__global__ void k_dif_pass(Fr* d, uint32_t log_n, uint32_t s0, uint32_t r, uint32_t c, const Fr* tab, sp1_ntt_src src,
                           Fr scale, bool do_scale) {
  extern __shared__ Fr sh[];
  Fr* roots = sh + (1u << (r + c));
  const uint32_t lanes = 1u << c;
  const uint32_t size = 1u << r;
  const uint32_t m = log_n - s0 - r;
  const uint64_t groups = 1ull << (m - c);
  const uint64_t high = blockIdx.x / groups;
  const uint64_t low0 = (blockIdx.x % groups) << c;
  const uint64_t base = high << (log_n - s0);
  const uint64_t n = 1ull << log_n;

  for (uint32_t k = threadIdx.x; k < size / 2; k += blockDim.x) roots[k] = pow_tab(tab, (uint64_t)k << (log_n - r));

  for (uint32_t e = threadIdx.x; e < (size << c); e += blockDim.x) {
    uint32_t lc = e & (lanes - 1), t = e >> c;
    uint64_t i = base + ((uint64_t)t << m) + low0 + lc;
    Fr x = s0 == 0 ? load(d, src, i, n) : d[i];
    if (do_scale) x = x * scale;
    sh[e] = x;
  }
  __syncthreads();

  for (int j = (int)r - 1; j >= 0; j--) {
    for (uint32_t e = threadIdx.x; e < (size << c) / 2; e += blockDim.x) {
      uint32_t lc = e & (lanes - 1), b = e >> c;
      uint32_t pos = b & ((1u << j) - 1);
      uint32_t i0 = ((b >> j) << (j + 1)) + pos, i1 = i0 + (1u << j);
      Fr u = sh[(i0 << c) + lc], v = sh[(i1 << c) + lc];
      sh[(i0 << c) + lc] = u + v;
      sh[(i1 << c) + lc] = (u - v) * roots[pos << (r - j - 1)];
    }
    __syncthreads();
  }

  for (uint32_t e = threadIdx.x; e < (size << c); e += blockDim.x) {
    uint32_t lc = e & (lanes - 1), t = e >> c;
    uint64_t low = low0 + lc;
    Fr x = sh[e];
    if (m > 0) x = x * pow_tab(tab, (low * rev(t, r)) << s0);
    d[base + ((uint64_t)t << m) + low] = x;
  }
}

constexpr uint32_t MAX_RADIX = 9;
constexpr uint32_t LANES = 2;

// The radices of the DIT passes, in order. The first pass has unit stride and needs no lanes; the
// others use MAX_RADIX - 1 to fit the lanes in shared memory. DIF passes use them in reverse.
uint32_t schedule(uint32_t log_n, uint32_t* rs) {
  uint32_t passes = log_n <= MAX_RADIX ? 1 : 1 + (log_n - MAX_RADIX + MAX_RADIX - 2) / (MAX_RADIX - 1);
  uint32_t s0 = 0;
  for (uint32_t p = 0; p < passes; p++) {
    uint32_t left = passes - p;
    uint32_t r = p == 0 ? log_n - (passes - 1) * (MAX_RADIX - 1) : (log_n - s0 + left - 1) / left;
    if (p == 0 && passes > 1 && r < (log_n + passes - 1) / passes) r = (log_n + passes - 1) / passes;
    if (r > MAX_RADIX - (p > 0)) r = MAX_RADIX - (p > 0);
    rs[p] = r;
    s0 += r;
  }
  return passes;
}

void launch_dit(Fr* d, uint32_t log_n, const Fr* tab, const Fr* coset, cudaStream_t s) {
  uint32_t rs[8];
  uint32_t passes = schedule(log_n, rs), s0 = 0;
  for (uint32_t p = 0; p < passes; p++) {
    uint32_t r = rs[p], c = s0 < LANES ? s0 : LANES;
    uint32_t threads = min((1u << (r + c)) / 2, 512u);
    size_t shmem = ((1u << (r + c)) + (1u << r) / 2) * sizeof(Fr);
    k_dit_pass<<<(unsigned)((1ull << log_n) >> (r + c)), threads, shmem, s>>>(d, log_n, s0, r, c, tab,
                                                                              p == 0 ? coset : nullptr);
    s0 += r;
  }
}

}  // namespace

extern "C" int sp1_ntt(void* data, uint32_t log_n, const void* tab, const sp1_fr* scale, void* stream) {
  cudaStream_t s = st(stream);
  Fr* d = reinterpret_cast<Fr*>(data);
  k_bitrev<<<blocks(1ull << log_n), THREADS, 0, s>>>(d, log_n, scale ? cst<Fr>(scale) : Fr::one(), scale != nullptr);
  launch_dit(d, log_n, reinterpret_cast<const Fr*>(tab), nullptr, s);
  return err();
}

extern "C" int sp1_ntt_dit(void* data, uint32_t log_n, const void* tab, const void* coset_tab, void* stream) {
  launch_dit(reinterpret_cast<Fr*>(data), log_n, reinterpret_cast<const Fr*>(tab),
             reinterpret_cast<const Fr*>(coset_tab), st(stream));
  return err();
}

extern "C" int sp1_ntt_dif(void* data, uint32_t log_n, const void* tab, const sp1_fr* scale, const sp1_ntt_src* src,
                           void* stream) {
  Fr* d = reinterpret_cast<Fr*>(data);
  sp1_ntt_src source = src ? *src : sp1_ntt_src{SP1_SRC_DATA, nullptr, nullptr, {}, {}};
  uint32_t rs[8];
  uint32_t passes = schedule(log_n, rs), s0 = 0;
  for (uint32_t p = 0; p < passes; p++) {
    uint32_t r = rs[passes - 1 - p], m = log_n - s0 - r, c = m < LANES ? m : LANES;
    uint32_t threads = min((1u << (r + c)) / 2, 512u);
    size_t shmem = ((1u << (r + c)) + (1u << r) / 2) * sizeof(Fr);
    k_dif_pass<<<(unsigned)((1ull << log_n) >> (r + c)), threads, shmem, st(stream)>>>(
        d, log_n, s0, r, c, reinterpret_cast<const Fr*>(tab), source, scale ? cst<Fr>(scale) : Fr::one(),
        p == 0 && scale != nullptr);
    s0 += r;
  }
  return err();
}

extern "C" int sp1_bitrev(void* data, uint32_t log_n, void* stream) {
  k_bitrev<<<blocks(1ull << log_n), THREADS, 0, st(stream)>>>(reinterpret_cast<Fr*>(data), log_n, Fr::one(), false);
  return err();
}
