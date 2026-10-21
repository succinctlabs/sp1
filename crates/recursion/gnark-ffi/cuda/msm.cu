#include <cub/cub.cuh>
#include <cuda_runtime.h>

#include "api.h"
#include "field.cuh"
#include "util.cuh"

namespace {

template <class F>
struct Affine {
  F x, y;  // gnark encodes infinity as (0, 0)
};

// Extended Jacobian coordinates: x = X / ZZ, y = Y / ZZZ, with ZZ = 0 for infinity.
template <class F>
struct Xyzz {
  F x, y, zz, zzz;

  __device__ static Xyzz inf() { return Xyzz{F::zero(), F::zero(), F::zero(), F::zero()}; }
  __device__ bool is_inf() const { return zz.is_zero(); }
};

template <class F>
__device__ Xyzz<F> dbl_affine(const F& x, const F& y) {
  if (y.is_zero()) return Xyzz<F>::inf();
  F u = y.dbl(), v = u.sqr(), w = u * v, s = x * v;
  F x2 = x.sqr();
  F m = x2.dbl() + x2;
  F x3 = m.sqr() - s.dbl();
  return Xyzz<F>{x3, m * (s - x3) - w * y, v, w};
}

template <class F>
__device__ Xyzz<F> dbl(const Xyzz<F>& p) {
  if (p.is_inf() || p.y.is_zero()) return Xyzz<F>::inf();
  F u = p.y.dbl(), v = u.sqr(), w = u * v, s = p.x * v;
  F x2 = p.x.sqr();
  F m = x2.dbl() + x2;
  F x3 = m.sqr() - s.dbl();
  return Xyzz<F>{x3, m * (s - x3) - w * p.y, v * p.zz, w * p.zzz};
}

template <class F>
__device__ Xyzz<F> add_affine(const Xyzz<F>& p, const Affine<F>& q, bool neg) {
  if (q.x.is_zero() && q.y.is_zero()) return p;
  F qy = neg ? -q.y : q.y;
  if (p.is_inf()) return Xyzz<F>{q.x, qy, F::one(), F::one()};
  F u2 = q.x * p.zz, s2 = qy * p.zzz;
  F pp_ = u2 - p.x, r = s2 - p.y;
  if (pp_.is_zero()) return r.is_zero() ? dbl_affine(q.x, qy) : Xyzz<F>::inf();
  F pp = pp_.sqr(), ppp = pp_ * pp, qq = p.x * pp;
  F x3 = r.sqr() - ppp - qq.dbl();
  return Xyzz<F>{x3, r * (qq - x3) - p.y * ppp, p.zz * pp, p.zzz * ppp};
}

template <class F>
__device__ Xyzz<F> add(const Xyzz<F>& p, const Xyzz<F>& q) {
  if (p.is_inf()) return q;
  if (q.is_inf()) return p;
  F u1 = p.x * q.zz, u2 = q.x * p.zz, s1 = p.y * q.zzz, s2 = q.y * p.zzz;
  F pp_ = u2 - u1, r = s2 - s1;
  if (pp_.is_zero()) return r.is_zero() ? dbl(p) : Xyzz<F>::inf();
  F pp = pp_.sqr(), ppp = pp_ * pp, qq = u1 * pp;
  F x3 = r.sqr() - ppp - qq.dbl();
  return Xyzz<F>{x3, r * (qq - x3) - s1 * ppp, p.zz * q.zz * pp, p.zzz * q.zzz * ppp};
}

constexpr uint32_t SIGN = 1u << 31;
#ifndef SP1_SEGMENT
#define SP1_SEGMENT 32
#endif
constexpr uint32_t SEGMENT = SP1_SEGMENT;

// The signed c-bit digit d of window w of each scalar becomes key |d| - 1, or the sentinel 2^(c-1) when
// d = 0, paired with the point index and the sign of d. The carries of the lower windows are recomputed.
__global__ void k_digits(const Fr* scalars, uint32_t n, uint32_t c, uint32_t window, uint32_t* keys, uint32_t* vals) {
  uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= n) return;
  Fr k = scalars[i].to_canonical();
  const uint32_t half = 1u << (c - 1);
  uint32_t carry = 0;
  int64_t d = 0;
  for (uint32_t w = 0; w <= window; w++) {
    uint32_t bit = w * c, limb = bit / 64, sh = bit % 64;
    uint64_t bits = limb < 4 ? k.v[limb] >> sh : 0;
    if (sh + c > 64 && limb + 1 < 4) bits |= k.v[limb + 1] << (64 - sh);
    d = (int64_t)(bits & ((1ull << c) - 1)) + carry;
    carry = d > half;
    if (carry) d -= (int64_t)1 << c;
  }
  keys[i] = d == 0 ? half : (uint32_t)(d < 0 ? -d : d) - 1;
  vals[i] = i | (d < 0 ? SIGN : 0);
}

// seg_run[s] = the run that segment s belongs to.
__global__ void k_segments(const uint32_t* counts, const uint32_t* seg_start, uint32_t runs, uint32_t* seg_run) {
  uint32_t r = blockIdx.x * blockDim.x + threadIdx.x;
  if (r >= runs) return;
  uint32_t nseg = (counts[r] + SEGMENT - 1) / SEGMENT;
  for (uint32_t k = 0; k < nseg; k++) seg_run[seg_start[r] + k] = r;
}

__global__ void k_nsegments(const uint32_t* counts, uint32_t runs, uint32_t* nseg) {
  uint32_t r = blockIdx.x * blockDim.x + threadIdx.x;
  if (r < runs) nseg[r] = (counts[r] + SEGMENT - 1) / SEGMENT;
}

// Sums the points of one segment of a run of sorted (key, point) pairs.
template <class F>
__global__ void k_sum_points(const Affine<F>* points, const uint32_t* vals, const uint32_t* unique,
                             const uint32_t* counts, const uint32_t* offsets, const uint32_t* seg_start,
                             const uint32_t* seg_run, uint32_t nsegs, Xyzz<F>* out, uint32_t* out_keys) {
  uint32_t s = blockIdx.x * blockDim.x + threadIdx.x;
  if (s >= nsegs) return;
  uint32_t r = seg_run[s], k = s - seg_start[r];
  uint32_t begin = offsets[r] + k * SEGMENT, end = min(offsets[r] + counts[r], begin + SEGMENT);
  // The next point is loaded before the current one is added, to overlap the random load with the
  // arithmetic.
  Xyzz<F> acc = Xyzz<F>::inf();
  uint32_t v = vals[begin];
  Affine<F> p = points[v & ~SIGN];
  for (uint32_t e = begin + 1; e < end; e++) {
    uint32_t vn = vals[e];
    Affine<F> pn = points[vn & ~SIGN];
    acc = add_affine(acc, p, (v & SIGN) != 0);
    v = vn;
    p = pn;
  }
  acc = add_affine(acc, p, (v & SIGN) != 0);
  out[s] = acc;
  out_keys[s] = unique[r];
}

// Sums one segment of a run of partial sums sharing a key.
template <class F>
__global__ void k_sum_partials(const Xyzz<F>* in, const uint32_t* unique, const uint32_t* counts,
                               const uint32_t* offsets, const uint32_t* seg_start, const uint32_t* seg_run,
                               uint32_t nsegs, Xyzz<F>* out, uint32_t* out_keys) {
  uint32_t s = blockIdx.x * blockDim.x + threadIdx.x;
  if (s >= nsegs) return;
  uint32_t r = seg_run[s], k = s - seg_start[r];
  uint32_t begin = offsets[r] + k * SEGMENT, end = min(offsets[r] + counts[r], begin + SEGMENT);
  Xyzz<F> acc = Xyzz<F>::inf();
  for (uint32_t e = begin; e < end; e++) acc = add(acc, in[e]);
  out[s] = acc;
  out_keys[s] = unique[r];
}

template <class F>
__global__ void k_place(Xyzz<F>* buckets, const Xyzz<F>* partials, const uint32_t* keys, uint32_t n) {
  uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i < n) buckets[keys[i]] = partials[i];
}

// For each range of buckets [lo, lo + len), computes sum_{b in range} (b + 1) * B_b, where bucket b
// holds the points whose digit is b + 1.
template <class F>
__global__ void k_bucket_ranges(const Xyzz<F>* b, uint32_t c, uint32_t ranges, Xyzz<F>* out) {
  uint32_t rg = blockIdx.x * blockDim.x + threadIdx.x;
  if (rg >= ranges) return;
  uint32_t len = (1u << (c - 1)) / ranges, lo = rg * len;
  Xyzz<F> run = Xyzz<F>::inf(), sum = Xyzz<F>::inf();
  for (uint32_t j = lo + len; j > lo; j--) {
    run = add(run, b[j - 1]);
    sum = add(sum, run);
  }
  // sum = sum_b (b - lo + 1) B_b; add lo * run.
  Xyzz<F> scaled = Xyzz<F>::inf();
  for (int bit = 31; bit >= 0; bit--) {
    scaled = dbl(scaled);
    if ((lo >> bit) & 1) scaled = add(scaled, run);
  }
  out[rg] = add(sum, scaled);
}

constexpr uint32_t REDUCE = 128;

// out[block] = sum of in[block * REDUCE .. (block + 1) * REDUCE).
template <class F>
__global__ void k_reduce(const Xyzz<F>* in, uint32_t n, Xyzz<F>* out) {
  __shared__ Xyzz<F> sh[REDUCE];
  uint32_t t = threadIdx.x, i = blockIdx.x * REDUCE + t;
  sh[t] = i < n ? in[i] : Xyzz<F>::inf();
  __syncthreads();
  for (uint32_t step = REDUCE / 2; step > 0; step /= 2) {
    if (t < step) sh[t] = add(sh[t], sh[t + step]);
    __syncthreads();
  }
  if (t == 0) out[blockIdx.x] = sh[0];
}

template <class T>
T* alloc(size_t n, cudaStream_t s) {
  T* p = nullptr;
  if (cudaMalloc(&p, n * sizeof(T)) != cudaSuccess) return nullptr;
  return p;
}

template <class F>
int msm(void* windows_out, uint32_t* nwindows, const void* scalars_ptr, const void* points_ptr, uint64_t n64, uint32_t c,
        uint32_t ranges, cudaStream_t s) {
  const Fr* scalars = reinterpret_cast<const Fr*>(scalars_ptr);
  const Affine<F>* points = reinterpret_cast<const Affine<F>*>(points_ptr);
  const uint32_t n = (uint32_t)n64;
  uint32_t windows = (254 + c - 1) / c;
  if (254 - (windows - 1) * c > c - 1) windows++;
  const uint32_t nbuckets = 1u << (c - 1), sentinel = nbuckets;
  if (ranges > nbuckets) ranges = nbuckets;

  const uint32_t max_runs = (n < nbuckets ? n : nbuckets) + 1;
  const uint32_t max_segs = n / SEGMENT + max_runs;
  uint32_t* keys[2] = {alloc<uint32_t>(n, s), alloc<uint32_t>(n, s)};
  uint32_t* vals[2] = {alloc<uint32_t>(n, s), alloc<uint32_t>(n, s)};
  uint32_t* unique = alloc<uint32_t>(max_segs, s);
  uint32_t* counts = alloc<uint32_t>(max_segs, s);
  uint32_t* offsets = alloc<uint32_t>(max_segs, s);
  uint32_t* seg_start = alloc<uint32_t>(max_segs, s);
  uint32_t* seg_run = alloc<uint32_t>(max_segs, s);
  uint32_t* num = alloc<uint32_t>(1, s);
  Xyzz<F>* part[2] = {alloc<Xyzz<F>>(max_segs, s), alloc<Xyzz<F>>(max_segs, s)};
  uint32_t* part_keys[2] = {alloc<uint32_t>(max_segs, s), alloc<uint32_t>(max_segs, s)};
  Xyzz<F>* buckets = alloc<Xyzz<F>>(nbuckets, s);
  Xyzz<F>* red[2] = {alloc<Xyzz<F>>(ranges, s), alloc<Xyzz<F>>(ranges, s)};
  Xyzz<F>* window_sums = alloc<Xyzz<F>>(windows, s);
  if (!keys[0] || !keys[1] || !vals[0] || !vals[1] || !unique || !counts || !offsets || !seg_start || !seg_run ||
      !num || !part[0] || !part[1] || !part_keys[0] || !part_keys[1] || !buckets || !red[0] || !red[1] || !window_sums)
    return (int)cudaErrorMemoryAllocation;

  size_t tmp_bytes = 0, need = 0;
  cub::DoubleBuffer<uint32_t> kb(keys[0], keys[1]), vb(vals[0], vals[1]);
  cub::DeviceRadixSort::SortPairs(nullptr, need, kb, vb, (int)n, 0, (int)c, s);
  tmp_bytes = need;
  cub::DeviceRunLengthEncode::Encode(nullptr, need, keys[0], unique, counts, num, (int)max_segs, s);
  tmp_bytes = need > tmp_bytes ? need : tmp_bytes;
  cub::DeviceScan::ExclusiveSum(nullptr, need, counts, offsets, (int)max_segs, s);
  tmp_bytes = need > tmp_bytes ? need : tmp_bytes;
  void* tmp = alloc<unsigned char>(tmp_bytes, s);
  if (!tmp) return (int)cudaErrorMemoryAllocation;

  // Run-length encodes sorted keys and lays out the segments of each run; returns the number of
  // segments. Zero digits all share the sentinel key, which sorts last; its run is dropped.
  auto segment = [&](const uint32_t* sorted_keys, uint32_t len, uint32_t* runs_out) -> uint32_t {
    size_t b = tmp_bytes;
    cub::DeviceRunLengthEncode::Encode(tmp, b, sorted_keys, unique, counts, num, (int)len, s);
    uint32_t runs, last_key;
    cudaMemcpyAsync(&runs, num, sizeof(uint32_t), cudaMemcpyDeviceToHost, s);
    cudaStreamSynchronize(s);
    cudaMemcpyAsync(&last_key, unique + runs - 1, sizeof(uint32_t), cudaMemcpyDeviceToHost, s);
    cudaStreamSynchronize(s);
    if (last_key == sentinel) runs--;
    *runs_out = runs;
    if (runs == 0) return 0;
    b = tmp_bytes;
    cub::DeviceScan::ExclusiveSum(tmp, b, counts, offsets, (int)runs, s);
    k_nsegments<<<blocks(runs), THREADS, 0, s>>>(counts, runs, seg_run);
    b = tmp_bytes;
    cub::DeviceScan::ExclusiveSum(tmp, b, seg_run, seg_start, (int)runs, s);
    uint32_t last_start, last_count;
    cudaMemcpyAsync(&last_start, seg_start + runs - 1, sizeof(uint32_t), cudaMemcpyDeviceToHost, s);
    cudaMemcpyAsync(&last_count, counts + runs - 1, sizeof(uint32_t), cudaMemcpyDeviceToHost, s);
    cudaStreamSynchronize(s);
    k_segments<<<blocks(runs), THREADS, 0, s>>>(counts, seg_start, runs, seg_run);
    return last_start + (last_count + SEGMENT - 1) / SEGMENT;
  };

  for (uint32_t w = 0; w < windows; w++) {
    kb = cub::DoubleBuffer<uint32_t>(keys[0], keys[1]);
    vb = cub::DoubleBuffer<uint32_t>(vals[0], vals[1]);
    k_digits<<<blocks(n), THREADS, 0, s>>>(scalars, n, c, w, kb.Current(), vb.Current());
    size_t b = tmp_bytes;
    cub::DeviceRadixSort::SortPairs(tmp, b, kb, vb, (int)n, 0, (int)c, s);
    cudaMemsetAsync(buckets, 0, nbuckets * sizeof(Xyzz<F>), s);

    uint32_t runs;
    uint32_t nsegs = segment(kb.Current(), n, &runs);
    if (nsegs > 0) {
      int cur = 0;
      k_sum_points<F><<<blocks(nsegs), THREADS, 0, s>>>(points, vb.Current(), unique, counts, offsets, seg_start,
                                                        seg_run, nsegs, part[cur], part_keys[cur]);
      while (nsegs > runs) {
        uint32_t next = segment(part_keys[cur], nsegs, &runs);
        k_sum_partials<F><<<blocks(next), THREADS, 0, s>>>(part[cur], unique, counts, offsets, seg_start, seg_run,
                                                           next, part[1 - cur], part_keys[1 - cur]);
        cur = 1 - cur;
        nsegs = next;
      }
      k_place<F><<<blocks(nsegs), THREADS, 0, s>>>(buckets, part[cur], part_keys[cur], nsegs);
    }

    k_bucket_ranges<F><<<blocks(ranges), THREADS, 0, s>>>(buckets, c, ranges, red[0]);
    uint32_t len = ranges;
    int cur = 0;
    while (len > 1) {
      uint32_t nb = (len + REDUCE - 1) / REDUCE;
      k_reduce<F><<<nb, REDUCE, 0, s>>>(red[cur], len, nb == 1 ? window_sums + w : red[1 - cur]);
      cur = 1 - cur;
      len = nb;
    }
    if (ranges == 1) cudaMemcpyAsync(window_sums + w, red[0], sizeof(Xyzz<F>), cudaMemcpyDeviceToDevice, s);
  }
  cudaMemcpyAsync(windows_out, window_sums, windows * sizeof(Xyzz<F>), cudaMemcpyDeviceToHost, s);
  cudaStreamSynchronize(s);
  *nwindows = windows;

  for (void* p : {(void*)keys[0], (void*)keys[1], (void*)vals[0], (void*)vals[1], (void*)unique, (void*)counts,
                  (void*)offsets, (void*)seg_start, (void*)seg_run, (void*)num, (void*)part[0], (void*)part[1],
                  (void*)part_keys[0], (void*)part_keys[1], (void*)buckets, (void*)red[0], (void*)red[1],
                  (void*)window_sums, tmp})
    cudaFree(p);
  return err();
}

}  // namespace

extern "C" int sp1_msm_g1(void* windows_out, uint32_t* nwindows, const void* scalars, const void* points, uint64_t n,
                          uint32_t c, void* stream) {
  return msm<Fp>(windows_out, nwindows, scalars, points, n, c, 4096, st(stream));
}

extern "C" int sp1_msm_g2(void* windows_out, uint32_t* nwindows, const void* scalars, const void* points, uint64_t n,
                          uint32_t c, void* stream) {
  return msm<Fp2>(windows_out, nwindows, scalars, points, n, c, 4096, st(stream));
}
