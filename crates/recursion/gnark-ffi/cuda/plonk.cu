#include <cub/cub.cuh>
#include <cuda_runtime.h>

#include "api.h"
#include "field.cuh"
#include "util.cuh"

namespace {

#define ELEMENTWISE(name, params, body)                           \
  __global__ void name params {                                   \
    uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x; \
    if (i < n) body;                                              \
  }

ELEMENTWISE(k_scale_pow, (Fr * dst, const Fr* src, uint64_t n, const Fr* tab), dst[i] = src[i] * pow_tab(tab, i))
ELEMENTWISE(k_mul, (Fr * out, const Fr* a, const Fr* b, uint64_t n), out[i] = a[i] * b[i])
ELEMENTWISE(k_fma, (Fr * acc, const Fr* a, const Fr* b, uint64_t n), acc[i] = acc[i] + a[i] * b[i])
ELEMENTWISE(k_fma3, (Fr * acc, const Fr* a, const Fr* b, const Fr* c, uint64_t n), acc[i] = acc[i] + a[i] * b[i] * c[i])
ELEMENTWISE(k_add, (Fr * acc, const Fr* a, uint64_t n), acc[i] = acc[i] + a[i])
ELEMENTWISE(k_sub, (Fr * acc, const Fr* a, uint64_t n), acc[i] = acc[i] - a[i])
ELEMENTWISE(k_axpy, (Fr * acc, const Fr* x, Fr s, uint64_t n), acc[i] = acc[i] + x[i] * s)
ELEMENTWISE(k_scale, (Fr * x, Fr s, uint64_t n), x[i] = x[i] * s)
ELEMENTWISE(k_expand, (Fr * dst, const uint16_t* idx, const Fr* table, uint64_t n), dst[i] = table[idx[i]])

__global__ void k_scatter(Fr* dst, const uint32_t* pos, const Fr* vals, uint64_t cnt) {
  uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  if (i < cnt) dst[pos[i]] = vals[i];
}

// v[j] += b(c * w^j), with b given by up to three coefficients.
__global__ void k_blind_coset(Fr* v, uint64_t n, const Fr* tab_w, Fr c, Fr b0, Fr b1, Fr b2, int nb) {
  uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  if (i >= n) return;
  Fr x = c * pow_tab(tab_w, i);
  Fr e = nb > 2 ? b2 : (nb > 1 ? b1 : b0);
  if (nb > 2) e = e * x + b1;
  if (nb > 1) e = e * x + b0;
  v[i] = v[i] + e;
}

// acc[j] (*)= v[j] + kbc * w^j + gamma.
__global__ void k_perm_id(Fr* acc, const Fr* v, uint64_t n, const Fr* tab_w, Fr kbc, Fr gamma, int init) {
  uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  if (i >= n) return;
  Fr f = v[i] + kbc * pow_tab(tab_w, i) + gamma;
  acc[i] = init ? f : acc[i] * f;
}

// acc[j] (*)= v[j] + beta * s[j] + gamma.
__global__ void k_perm_s(Fr* acc, const Fr* v, const Fr* s, uint64_t n, Fr beta, Fr gamma, int init) {
  uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  if (i >= n) return;
  Fr f = v[i] + beta * s[i] + gamma;
  acc[i] = init ? f : acc[i] * f;
}

constexpr int ZC_CHUNK = 8;

// acc += alpha * (p_s * z[j+1] - p_id * z[j]) + alpha2_l1 * (z[j] - 1) / (x_j - 1), with x_j = c * w^j.
__global__ void k_z_combine(Fr* acc, const Fr* p_id, const Fr* p_s, const Fr* z, uint64_t n, const Fr* tab_w, Fr c,
                            Fr alpha, Fr alpha2_l1) {
  uint64_t base = (blockIdx.x * (uint64_t)blockDim.x + threadIdx.x) * ZC_CHUNK;
  if (base >= n) return;
  int len = (int)min((uint64_t)ZC_CHUNK, n - base);
  Fr d[ZC_CHUNK], pre[ZC_CHUNK];
  Fr run = Fr::one();
  for (int e = 0; e < len; e++) {
    d[e] = c * pow_tab(tab_w, base + e) - Fr::one();
    pre[e] = run;
    run = run * d[e];
  }
  Fr r = run.inverse();
  for (int e = len - 1; e >= 0; e--) {
    uint64_t i = base + e;
    Fr di = r * pre[e];
    r = r * d[e];
    Fr zi = z[i], zs = z[i + 1 == n ? 0 : i + 1];
    Fr ord = p_s[i] * zs - p_id[i] * zi;
    acc[i] = acc[i] + ord * alpha + (zi - Fr::one()) * di * alpha2_l1;
  }
}

// h[t*n + i] (+)= w[t] * c^-i * g[bitrev(i)] for t < 3, and for t = 3 when i < 8.
__global__ void k_h_accum(Fr* h, const Fr* g, uint64_t n, uint32_t log_n, const Fr* ctab_inv, Fr w0, Fr w1, Fr w2, Fr w3,
                          int init) {
  uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  if (i >= n) return;
  Fr x = g[__brev((uint32_t)i) >> (32 - log_n)] * pow_tab(ctab_inv, i);
  Fr ws[4] = {w0, w1, w2, w3};
  int tmax = i < 8 ? 4 : 3;
  for (int t = 0; t < tmax; t++) {
    Fr y = x * ws[t];
    uint64_t idx = t * n + i;
    h[idx] = init ? y : h[idx] + y;
  }
}

constexpr int RATIO_CHUNK = 8;

// z[i+1] = prod_j (f_j[i] + beta*k_j*w^i + gamma) / prod_j (f_j[i] + beta*id(sigma_j(i)) + gamma); z[0] = 1,
// where f_j[i] = values[wires[j*n + i]].
__global__ void k_ratio(Fr* z, const Fr* values, const uint32_t* wires, const uint32_t* sigma, uint64_t n, const Fr* tab_w,
                        Fr beta, Fr gamma, Fr u, Fr u2) {
  uint64_t base = (blockIdx.x * (uint64_t)blockDim.x + threadIdx.x) * RATIO_CHUNK;
  if (base >= n - 1) return;
  if (base == 0) z[0] = Fr::one();
  int len = (int)min((uint64_t)RATIO_CHUNK, n - 1 - base);
  Fr num[RATIO_CHUNK], den[RATIO_CHUNK], pre[RATIO_CHUNK];
  Fr bu = beta * u, bu2 = beta * u2;
  Fr run = Fr::one();
  for (int e = 0; e < len; e++) {
    uint64_t i = base + e;
    Fr w = pow_tab(tab_w, i);
    Fr fl = values[wires[i]], fr = values[wires[n + i]], fo = values[wires[2 * n + i]];
    num[e] = (fl + beta * w + gamma) * (fr + bu * w + gamma) * (fo + bu2 * w + gamma);
    den[e] = (fl + beta * id_value(sigma[i], n, tab_w, u, u2) + gamma) *
             (fr + beta * id_value(sigma[n + i], n, tab_w, u, u2) + gamma) *
             (fo + beta * id_value(sigma[2 * n + i], n, tab_w, u, u2) + gamma);
    pre[e] = run;
    run = run * den[e];
  }
  Fr rinv = run.inverse();
  for (int e = len - 1; e >= 0; e--) {
    Fr di = rinv * pre[e];
    rinv = rinv * den[e];
    z[base + e + 1] = num[e] * di;
  }
}

// Evaluate the six unblinded PLONK polynomials with the same Lagrange weights.
// A product tree gives all denominators in a tile with one field inversion.
constexpr int EVAL_TILE = 128;
__global__ void k_lagrange_openings(Fr* partial, const Fr* values, const uint32_t* wires,
                                    const uint32_t* sigma, const Fr* qcp, uint64_t n, const Fr* tab,
                                    Fr u, Fr u2, Fr zeta, Fr scale) {
  __shared__ Fr tree[2 * EVAL_TILE];
  const int lane = threadIdx.x;
  Fr sums[6] = {};
  for (uint64_t base = (uint64_t)blockIdx.x * EVAL_TILE; base < n; base += (uint64_t)gridDim.x * EVAL_TILE) {
    uint64_t i = base + lane;
    Fr w = pow_tab(tab, i % n);
    Fr weight;
    if (scale.is_zero()) {
      // zeta is itself a node of the interpolation domain.
      weight = w == zeta ? Fr::one() : Fr::zero();
    } else {
      tree[EVAL_TILE + lane] = i < n ? zeta - w : Fr::one();
      for (int width = EVAL_TILE / 2; width; width /= 2) {
        __syncthreads();
        if (lane < width) tree[width + lane] = tree[2 * (width + lane)] * tree[2 * (width + lane) + 1];
      }
      if (lane == 0) tree[1] = tree[1].inverse();
      for (int width = 1; width < EVAL_TILE; width *= 2) {
        __syncthreads();
        if (lane < width) {
          int child = 2 * (width + lane);
          Fr left = tree[child], right = tree[child + 1], parent = tree[width + lane];
          tree[child] = parent * right;
          tree[child + 1] = parent * left;
        }
      }
      __syncthreads();
      weight = scale * w * tree[EVAL_TILE + lane];
    }
    if (i < n) {
#pragma unroll
      for (int j = 0; j < 3; j++) sums[j] = sums[j] + weight * values[wires[(uint64_t)j * n + i]];
#pragma unroll
      for (int j = 0; j < 2; j++) sums[j + 3] = sums[j + 3] + weight * id_value(sigma[(uint64_t)j * n + i], n, tab, u, u2);
      if (!qcp[i].is_zero()) sums[5] = sums[5] + weight;
    }
    __syncthreads();
  }
#pragma unroll
  for (int j = 0; j < 6; j++) {
    tree[lane] = sums[j];
    for (int stride = EVAL_TILE / 2; stride; stride /= 2) {
      __syncthreads();
      if (lane < stride) tree[lane] = tree[lane] + tree[lane + stride];
    }
    if (lane == 0) partial[(uint64_t)j * gridDim.x + blockIdx.x] = tree[0];
    __syncthreads();
  }
}

__global__ void k_opening_totals(Fr* out, const Fr* partial, int count) {
  __shared__ Fr sums[EVAL_TILE];
  int lane = threadIdx.x;
  Fr sum = Fr::zero();
  for (int i = lane; i < count; i += EVAL_TILE) sum = sum + partial[blockIdx.x * count + i];
  sums[lane] = sum;
  for (int stride = EVAL_TILE / 2; stride; stride /= 2) {
    __syncthreads();
    if (lane < stride) sums[lane] = sums[lane] + sums[lane + stride];
  }
  if (lane == 0) out[blockIdx.x] = sums[0];
}

// out[t] = sum_{i in chunk t} p_i z^(i - t*chunk).
__global__ void k_eval_partials(Fr* out, const Fr* p, uint64_t len, Fr z, uint64_t chunk) {
  uint64_t t = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  uint64_t s = t * chunk;
  if (s >= len) return;
  uint64_t e = min(len, s + chunk);
  Fr acc = Fr::zero();
  for (uint64_t i = e; i > s; i--) acc = acc * z + p[i - 1];
  out[t] = acc;
}

// q_i = f_{i+1} + a q_{i+1}; chunk t starts from carries[t+1] = q_{e_t - 1} and writes q_i for i in [max(s_t - 1, 0), e_t - 2].
__global__ void k_div_xma(Fr* out, const Fr* f, uint64_t len, Fr a, const Fr* carries, uint64_t chunk) {
  uint64_t t = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  uint64_t s = t * chunk;
  if (s >= len) return;
  uint64_t e = min(len, s + chunk);
  Fr q = carries[t + 1];
  for (uint64_t i = e - 1; i >= s && i >= 1; i--) {
    q = f[i] + a * q;
    out[i - 1] = q;
  }
}

struct MulOp {
  __device__ __forceinline__ Fr operator()(const Fr& a, const Fr& b) const { return a * b; }
};

template <class T>
T* dev(void* p) {
  return reinterpret_cast<T*>(p);
}

template <class T>
const T* dev(const void* p) {
  return reinterpret_cast<const T*>(p);
}

// Copies host values to a temporary device buffer; the caller frees it on the same stream.
template <class T>
T* upload_tmp(const void* host, uint64_t count, cudaStream_t s) {
  T* d = nullptr;
  if (cudaMallocAsync(&d, count * sizeof(T), s) != cudaSuccess) return nullptr;
  cudaMemcpyAsync(d, host, count * sizeof(T), cudaMemcpyHostToDevice, s);
  return d;
}

__global__ void k_qap_rows(Fr* a, Fr* b, Fr* c, const Fr* values, const Fr* coeffs, const uint8_t* terms,
                           const uint32_t* starts, uint32_t width, uint32_t coeff_bits, uint32_t rows, uint32_t n) {
  uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= n) return;
  Fr left = Fr::zero(), right = Fr::zero();
  if (i < rows) {
    for (uint32_t j = starts[i]; j < starts[i + 1]; ++j) {
      const uint8_t* data = terms + (uint64_t)j * width;
      uint64_t t = 0;
      for (uint32_t k = 0; k < width; ++k) t |= (uint64_t)data[k] << (8 * k);
      const uint32_t side = t & 3;
      if (side == 2) break;  // Terms are packed in L, R, O order.
      const uint32_t cid = (t >> 2) & ((1ull << coeff_bits) - 1);
      // gnark reserves coefficient IDs 0, 1, 2 and 3 for 0, 1, 2 and -1.
      if (cid == 0) continue;
      Fr v = values[t >> (2 + coeff_bits)];
      if (cid == 2) v = v.dbl();
      else if (cid == 3) v = -v;
      else if (cid != 1) v = v * coeffs[cid];
      if (side == 0) left = left + v;
      else right = right + v;
    }
  }
  a[i] = left;
  b[i] = right;
  c[i] = left * right;
}

}  // namespace

extern "C" {

int sp1_fr_scale_pow(void* dst, const void* src, uint64_t n, const void* tab, void* s) {
  k_scale_pow<<<blocks(n), THREADS, 0, st(s)>>>(dev<Fr>(dst), dev<Fr>(src), n, dev<Fr>(tab));
  return err();
}

int sp1_fr_mul(void* out, const void* a, const void* b, uint64_t n, void* s) {
  k_mul<<<blocks(n), THREADS, 0, st(s)>>>(dev<Fr>(out), dev<Fr>(a), dev<Fr>(b), n);
  return err();
}

int sp1_fr_fma(void* acc, const void* a, const void* b, uint64_t n, void* s) {
  k_fma<<<blocks(n), THREADS, 0, st(s)>>>(dev<Fr>(acc), dev<Fr>(a), dev<Fr>(b), n);
  return err();
}

int sp1_fr_fma3(void* acc, const void* a, const void* b, const void* c, uint64_t n, void* s) {
  k_fma3<<<blocks(n), THREADS, 0, st(s)>>>(dev<Fr>(acc), dev<Fr>(a), dev<Fr>(b), dev<Fr>(c), n);
  return err();
}

int sp1_fr_add(void* acc, const void* a, uint64_t n, void* s) {
  k_add<<<blocks(n), THREADS, 0, st(s)>>>(dev<Fr>(acc), dev<Fr>(a), n);
  return err();
}

int sp1_fr_sub(void* acc, const void* a, uint64_t n, void* s) {
  k_sub<<<blocks(n), THREADS, 0, st(s)>>>(dev<Fr>(acc), dev<Fr>(a), n);
  return err();
}

int sp1_fr_axpy(void* acc, const void* x, const sp1_fr* sc, uint64_t n, void* s) {
  k_axpy<<<blocks(n), THREADS, 0, st(s)>>>(dev<Fr>(acc), dev<Fr>(x), cst<Fr>(sc), n);
  return err();
}

int sp1_fr_scale(void* x, const sp1_fr* sc, uint64_t n, void* s) {
  k_scale<<<blocks(n), THREADS, 0, st(s)>>>(dev<Fr>(x), cst<Fr>(sc), n);
  return err();
}

int sp1_fr_blind_coset(void* v, uint64_t n, const void* tab_w, const sp1_fr* c, const sp1_fr* b, int nb, void* s) {
  Fr z = Fr::zero();
  k_blind_coset<<<blocks(n), THREADS, 0, st(s)>>>(dev<Fr>(v), n, dev<Fr>(tab_w), cst<Fr>(c), cst<Fr>(&b[0]),
                                                   nb > 1 ? cst<Fr>(&b[1]) : z, nb > 2 ? cst<Fr>(&b[2]) : z, nb);
  return err();
}

int sp1_fr_perm_id(void* acc, const void* v, uint64_t n, const void* tab_w, const sp1_fr* kbc, const sp1_fr* gamma, int init,
                   void* s) {
  k_perm_id<<<blocks(n), THREADS, 0, st(s)>>>(dev<Fr>(acc), dev<Fr>(v), n, dev<Fr>(tab_w), cst<Fr>(kbc), cst<Fr>(gamma),
                                               init);
  return err();
}

int sp1_fr_perm_s(void* acc, const void* v, const void* sv, uint64_t n, const sp1_fr* beta, const sp1_fr* gamma, int init,
                  void* s) {
  k_perm_s<<<blocks(n), THREADS, 0, st(s)>>>(dev<Fr>(acc), dev<Fr>(v), dev<Fr>(sv), n, cst<Fr>(beta), cst<Fr>(gamma), init);
  return err();
}

int sp1_fr_z_combine(void* acc, const void* p_id, const void* p_s, const void* z, uint64_t n, const void* tab_w,
                     const sp1_fr* c, const sp1_fr* alpha, const sp1_fr* alpha2_l1, void* s) {
  uint64_t threads = (n + ZC_CHUNK - 1) / ZC_CHUNK;
  k_z_combine<<<blocks(threads), THREADS, 0, st(s)>>>(dev<Fr>(acc), dev<Fr>(p_id), dev<Fr>(p_s), dev<Fr>(z), n,
                                                       dev<Fr>(tab_w), cst<Fr>(c), cst<Fr>(alpha), cst<Fr>(alpha2_l1));
  return err();
}

int sp1_fr_h_accum(void* h, const void* g, uint64_t n, const void* ctab_inv, const sp1_fr* w, int init, void* s) {
  uint32_t log_n = 63 - __builtin_clzll(n);
  k_h_accum<<<blocks(n), THREADS, 0, st(s)>>>(dev<Fr>(h), dev<Fr>(g), n, log_n, dev<Fr>(ctab_inv), cst<Fr>(&w[0]),
                                               cst<Fr>(&w[1]), cst<Fr>(&w[2]), cst<Fr>(&w[3]), init);
  return err();
}

int sp1_fr_ratio(void* z, const void* values, const uint32_t* wires, const uint32_t* sigma, uint64_t n, const void* tab_w,
                 const sp1_fr* beta, const sp1_fr* gamma, const sp1_fr* u, const sp1_fr* u2, void* s) {
  uint64_t threads = (n - 1 + RATIO_CHUNK - 1) / RATIO_CHUNK;
  k_ratio<<<blocks(threads), THREADS, 0, st(s)>>>(dev<Fr>(z), dev<Fr>(values), wires, sigma, n, dev<Fr>(tab_w),
                                                   cst<Fr>(beta), cst<Fr>(gamma), cst<Fr>(u), cst<Fr>(u2));
  return err();
}

int sp1_fr_scan_mul(void* z, uint64_t n, void* s) {
  Fr* p = dev<Fr>(z);
  size_t tmp_bytes = 0;
  cub::DeviceScan::InclusiveScan(nullptr, tmp_bytes, p, p, MulOp(), (int64_t)n, st(s));
  void* tmp;
  if (cudaMallocAsync(&tmp, tmp_bytes, st(s)) != cudaSuccess) return err();
  cub::DeviceScan::InclusiveScan(tmp, tmp_bytes, p, p, MulOp(), (int64_t)n, st(s));
  cudaFreeAsync(tmp, st(s));
  return err();
}

int sp1_plonk_lagrange_openings(sp1_fr* out, const void* values, const uint32_t* wires, const uint32_t* sigma,
                                const void* qcp, uint64_t n, const void* tab, const sp1_fr* u, const sp1_fr* u2,
                                const sp1_fr* zeta, const sp1_fr* scale, void* stream) {
  auto s = st(stream);
  int count = (int)std::min<uint64_t>((n + EVAL_TILE - 1) / EVAL_TILE, 8192);
  Fr* scratch;
  auto status = cudaMallocAsync(&scratch, (6 * count + 6) * sizeof(Fr), s);
  if (status != cudaSuccess) return (int)status;
  Fr* result = scratch + 6 * count;
  k_lagrange_openings<<<count, EVAL_TILE, 0, s>>>(scratch, dev<Fr>(values), wires, sigma, dev<Fr>(qcp), n,
      dev<Fr>(tab), cst<Fr>(u), cst<Fr>(u2), cst<Fr>(zeta), cst<Fr>(scale));
  k_opening_totals<<<6, EVAL_TILE, 0, s>>>(result, scratch, count);
  status = cudaMemcpyAsync(out, result, 6 * sizeof(Fr), cudaMemcpyDeviceToHost, s);
  cudaFreeAsync(scratch, s);
  return (int)(status == cudaSuccess ? cudaStreamSynchronize(s) : status);
}

int sp1_fr_eval_partials(sp1_fr* out, const void* p, uint64_t len, const sp1_fr* z, uint64_t chunk, void* s) {
  uint64_t nt = (len + chunk - 1) / chunk;
  Fr* d;
  if (cudaMallocAsync(&d, nt * sizeof(Fr), st(s)) != cudaSuccess) return err();
  k_eval_partials<<<blocks(nt), THREADS, 0, st(s)>>>(d, dev<Fr>(p), len, cst<Fr>(z), chunk);
  cudaMemcpyAsync(out, d, nt * sizeof(Fr), cudaMemcpyDeviceToHost, st(s));
  cudaFreeAsync(d, st(s));
  cudaStreamSynchronize(st(s));
  return err();
}

int sp1_fr_div_xma(void* out, const void* f, uint64_t len, const sp1_fr* a, const sp1_fr* carries, uint64_t chunk, void* s) {
  uint64_t nt = (len + chunk - 1) / chunk;
  Fr* d = upload_tmp<Fr>(carries, nt + 1, st(s));
  if (!d) return err();
  k_div_xma<<<blocks(nt), THREADS, 0, st(s)>>>(dev<Fr>(out), dev<Fr>(f), len, cst<Fr>(a), d, chunk);
  cudaFreeAsync(d, st(s));
  cudaStreamSynchronize(st(s));
  return err();
}


int sp1_fr_scatter(void* dst, const uint32_t* pos, const sp1_fr* vals, uint64_t cnt, void* s) {
  Fr* d = upload_tmp<Fr>(vals, cnt, st(s));
  if (!d) return err();
  k_scatter<<<blocks(cnt), THREADS, 0, st(s)>>>(dev<Fr>(dst), pos, d, cnt);
  cudaFreeAsync(d, st(s));
  cudaStreamSynchronize(st(s));
  return err();
}

int sp1_fr_expand(void* dst, const uint16_t* idx, const sp1_fr* table, uint32_t table_len, uint64_t n, void* s) {
  Fr* d = upload_tmp<Fr>(table, table_len, st(s));
  if (!d) return err();
  k_expand<<<blocks(n), THREADS, 0, st(s)>>>(dev<Fr>(dst), idx, d, n);
  cudaFreeAsync(d, st(s));
  cudaStreamSynchronize(st(s));
  return err();
}

int sp1_qap_rows(void* a, void* b, void* c, const void* values, const void* coeffs, const uint8_t* terms,
                 const uint32_t* starts, uint32_t width, uint32_t coeff_bits, uint32_t rows, uint32_t n) {
  k_qap_rows<<<blocks(n), THREADS>>>((Fr*)a, (Fr*)b, (Fr*)c, (const Fr*)values, (const Fr*)coeffs,
                                    terms, starts, width, coeff_bits, rows, n);
  return err();
}

int sp1_free_memory(uint64_t* bytes) {
  size_t available = 0, total = 0;
  auto result = cudaMemGetInfo(&available, &total);
  *bytes = available;
  return (int)result;
}

// Large buffers are not taken from the stream-ordered pool, whose caching costs gigabytes at these sizes.
int sp1_malloc(void** ptr, uint64_t size, void*) { return (int)cudaMalloc(ptr, size); }

int sp1_free(void* ptr, void* s) {
  cudaStreamSynchronize(st(s));
  return (int)cudaFree(ptr);
}
int sp1_host_register(void* ptr, uint64_t size) { return (int)cudaHostRegister(ptr, size, cudaHostRegisterDefault); }

int sp1_memcpy_h2d(void* dst, const void* src, uint64_t size, void* s) {
  return (int)cudaMemcpyAsync(dst, src, size, cudaMemcpyHostToDevice, st(s));
}

int sp1_memcpy_d2h(void* dst, const void* src, uint64_t size, void* s) {
  return (int)cudaMemcpyAsync(dst, src, size, cudaMemcpyDeviceToHost, st(s));
}

int sp1_memset(void* dst, uint64_t size, void* s) { return (int)cudaMemsetAsync(dst, 0, size, st(s)); }
int sp1_sync(void* s) { return (int)cudaStreamSynchronize(st(s)); }

int sp1_stream_create(void** s) {
  return (int)cudaStreamCreateWithFlags(reinterpret_cast<cudaStream_t*>(s), cudaStreamNonBlocking);
}

int sp1_event_create(void** e) {
  return (int)cudaEventCreateWithFlags(reinterpret_cast<cudaEvent_t*>(e), cudaEventDisableTiming);
}

int sp1_event_record(void* e, void* s) { return (int)cudaEventRecord(reinterpret_cast<cudaEvent_t>(e), st(s)); }
int sp1_stream_wait(void* s, void* e) { return (int)cudaStreamWaitEvent(st(s), reinterpret_cast<cudaEvent_t>(e), 0); }


int sp1_trim_pool(void) {
  int device;
  cudaMemPool_t pool;
  if (cudaGetDevice(&device) != cudaSuccess || cudaDeviceGetDefaultMemPool(&pool, device) != cudaSuccess) return err();
  // The pool keeps asynchronous frees until the host has seen them complete.
  if (cudaDeviceSynchronize() != cudaSuccess) return err();
  return (int)cudaMemPoolTrimTo(pool, 0);
}
}
