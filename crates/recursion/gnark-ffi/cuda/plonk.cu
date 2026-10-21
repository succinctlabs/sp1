#include "plonk.h"

#include <cub/cub.cuh>
#include <cuda_runtime.h>

namespace {

struct F {
  uint64_t v[4];
};

constexpr uint64_t Q0 = 0x43e1f593f0000001ULL;
constexpr uint64_t Q1 = 0x2833e84879b97091ULL;
constexpr uint64_t Q2 = 0xb85045b68181585dULL;
constexpr uint64_t Q3 = 0x30644e72e131a029ULL;
constexpr uint64_t QINV = 0xc2e1f593efffffffULL;

constexpr int THREADS = 256;
constexpr int TAB_LO_BITS = 12;
constexpr uint64_t TAB_LO = 1ULL << TAB_LO_BITS;

__device__ __forceinline__ bool geq_q(const uint64_t t[4]) {
  if (t[3] != Q3) return t[3] > Q3;
  if (t[2] != Q2) return t[2] > Q2;
  if (t[1] != Q1) return t[1] > Q1;
  return t[0] >= Q0;
}

__device__ __forceinline__ void sub_q(uint64_t t[4]) {
  unsigned __int128 d = (unsigned __int128)t[0] - Q0;
  t[0] = (uint64_t)d;
  uint64_t b = (uint64_t)(d >> 64) & 1;
  d = (unsigned __int128)t[1] - Q1 - b;
  t[1] = (uint64_t)d;
  b = (uint64_t)(d >> 64) & 1;
  d = (unsigned __int128)t[2] - Q2 - b;
  t[2] = (uint64_t)d;
  b = (uint64_t)(d >> 64) & 1;
  t[3] = t[3] - Q3 - b;
}

__device__ __forceinline__ F mul(const F& a, const F& b) {
  uint64_t t[6] = {0, 0, 0, 0, 0, 0};
#pragma unroll
  for (int i = 0; i < 4; i++) {
    uint64_t c = 0;
#pragma unroll
    for (int j = 0; j < 4; j++) {
      unsigned __int128 acc = (unsigned __int128)a.v[j] * b.v[i] + t[j] + c;
      t[j] = (uint64_t)acc;
      c = (uint64_t)(acc >> 64);
    }
    unsigned __int128 acc = (unsigned __int128)t[4] + c;
    t[4] = (uint64_t)acc;
    t[5] = (uint64_t)(acc >> 64);
    uint64_t m = t[0] * QINV;
    acc = (unsigned __int128)m * Q0 + t[0];
    c = (uint64_t)(acc >> 64);
    acc = (unsigned __int128)m * Q1 + t[1] + c;
    t[0] = (uint64_t)acc;
    c = (uint64_t)(acc >> 64);
    acc = (unsigned __int128)m * Q2 + t[2] + c;
    t[1] = (uint64_t)acc;
    c = (uint64_t)(acc >> 64);
    acc = (unsigned __int128)m * Q3 + t[3] + c;
    t[2] = (uint64_t)acc;
    c = (uint64_t)(acc >> 64);
    acc = (unsigned __int128)t[4] + c;
    t[3] = (uint64_t)acc;
    t[4] = t[5] + (uint64_t)(acc >> 64);
  }
  F r = {{t[0], t[1], t[2], t[3]}};
  if (geq_q(r.v)) sub_q(r.v);
  return r;
}

__device__ __forceinline__ F add(const F& a, const F& b) {
  F r;
  uint64_t c = 0;
#pragma unroll
  for (int i = 0; i < 4; i++) {
    unsigned __int128 s = (unsigned __int128)a.v[i] + b.v[i] + c;
    r.v[i] = (uint64_t)s;
    c = (uint64_t)(s >> 64);
  }
  if (geq_q(r.v)) sub_q(r.v);
  return r;
}

__device__ __forceinline__ F sub(const F& a, const F& b) {
  F r;
  uint64_t br = 0;
#pragma unroll
  for (int i = 0; i < 4; i++) {
    unsigned __int128 d = (unsigned __int128)a.v[i] - b.v[i] - br;
    r.v[i] = (uint64_t)d;
    br = (uint64_t)(d >> 64) & 1;
  }
  if (br) {
    uint64_t c = 0;
    const uint64_t q[4] = {Q0, Q1, Q2, Q3};
#pragma unroll
    for (int i = 0; i < 4; i++) {
      unsigned __int128 s = (unsigned __int128)r.v[i] + q[i] + c;
      r.v[i] = (uint64_t)s;
      c = (uint64_t)(s >> 64);
    }
  }
  return r;
}

__device__ __forceinline__ F one() {
  return F{{0xac96341c4ffffffbULL, 0x36fc76959f60cd29ULL, 0x666ea36f7879462eULL, 0x0e0a77c19a07df2fULL}};
}

__device__ __forceinline__ F load(const void* p, uint64_t i) {
  const F r2 = {{0x1bb8e645ae216da7ULL, 0x53fe3ab1e35c59e3ULL, 0x8c49833d53bb8085ULL, 0x0216d0b17f4e44a5ULL}};
  return mul(reinterpret_cast<const F*>(p)[i], r2);
}

__device__ __forceinline__ void store(void* p, uint64_t i, const F& x) {
  const F raw_one = {{1, 0, 0, 0}};
  reinterpret_cast<F*>(p)[i] = mul(x, raw_one);
}

__device__ __forceinline__ F inv(const F& x) {
  const uint64_t e[4] = {Q0 - 2, Q1, Q2, Q3};
  F r = one();
  for (int i = 3; i >= 0; i--) {
    for (int b = 63; b >= 0; b--) {
      r = mul(r, r);
      if ((e[i] >> b) & 1) r = mul(r, x);
    }
  }
  return r;
}

__device__ __forceinline__ F pow_tab(const F* tab, uint64_t j) {
  return mul(tab[j & (TAB_LO - 1)], tab[TAB_LO + (j >> TAB_LO_BITS)]);
}

__host__ __device__ __forceinline__ F cst(const sp1_fr* p) { return *reinterpret_cast<const F*>(p); }

struct MulOp {
  __device__ __forceinline__ F operator()(const F& a, const F& b) const { return mul(a, b); }
};

inline unsigned blocks(uint64_t n) { return (unsigned)((n + THREADS - 1) / THREADS); }
inline cudaStream_t st(void* s) { return reinterpret_cast<cudaStream_t>(s); }
inline int err() { return (int)cudaGetLastError(); }

__global__ void k_from_mont(F* x, uint64_t n) {
  uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  if (i < n) store(x, i, x[i]);
}

__global__ void k_scale_pow(void* dst, const void* src, uint64_t n, const F* tab) {
  uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  if (i < n) store(dst, i, mul(load(src, i), pow_tab(tab, i)));
}

__global__ void k_mul(void* out, const void* a, const void* b, uint64_t n) {
  uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  if (i < n) store(out, i, mul(load(a, i), load(b, i)));
}

__global__ void k_fma(void* acc, const void* a, const void* b, uint64_t n) {
  uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  if (i < n) store(acc, i, add(load(acc, i), mul(load(a, i), load(b, i))));
}

__global__ void k_fma3(void* acc, const void* a, const void* b, const void* c, uint64_t n) {
  uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  if (i < n) store(acc, i, add(load(acc, i), mul(mul(load(a, i), load(b, i)), load(c, i))));
}

__global__ void k_add(void* acc, const void* a, uint64_t n) {
  uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  if (i < n) store(acc, i, add(load(acc, i), load(a, i)));
}

__global__ void k_sub(void* acc, const void* a, uint64_t n) {
  uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  if (i < n) store(acc, i, sub(load(acc, i), load(a, i)));
}

__global__ void k_axpy(void* acc, const void* x, F s, uint64_t n) {
  uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  if (i < n) store(acc, i, add(load(acc, i), mul(load(x, i), s)));
}

__global__ void k_blind_coset(void* v, uint64_t n, const F* tab_w, F c, F b0, F b1, F b2, int nb) {
  uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  if (i >= n) return;
  F x = mul(c, pow_tab(tab_w, i));
  F e = nb > 2 ? b2 : (nb > 1 ? b1 : b0);
  if (nb > 2) e = add(mul(e, x), b1);
  if (nb > 1) e = add(mul(e, x), b0);
  store(v, i, add(load(v, i), e));
}

__global__ void k_perm_id(void* acc, const void* v, uint64_t n, const F* tab_w, F kbc, F gamma, int init) {
  uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  if (i >= n) return;
  F f = add(add(load(v, i), mul(kbc, pow_tab(tab_w, i))), gamma);
  store(acc, i, init ? f : mul(load(acc, i), f));
}

__global__ void k_perm_s(void* acc, const void* v, const void* s, uint64_t n, F beta, F gamma, int init) {
  uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  if (i >= n) return;
  F f = add(add(load(v, i), mul(beta, load(s, i))), gamma);
  store(acc, i, init ? f : mul(load(acc, i), f));
}

constexpr int ZC_CHUNK = 8;

// acc += alpha * (p_s * z[j+1] - p_id * z[j]) + alpha2_l1 * (z[j] - 1) / (x_j - 1)
__global__ void k_z_combine(void* acc, const void* p_id, const void* p_s, const void* z, uint64_t n, const F* tab_w, F c, F alpha, F alpha2_l1) {
  uint64_t base = (blockIdx.x * (uint64_t)blockDim.x + threadIdx.x) * ZC_CHUNK;
  if (base >= n) return;
  int len = (int)min((uint64_t)ZC_CHUNK, n - base);
  F d[ZC_CHUNK], pre[ZC_CHUNK];
  F run = one();
  for (int e = 0; e < len; e++) {
    d[e] = sub(mul(c, pow_tab(tab_w, base + e)), one());
    pre[e] = run;
    run = mul(run, d[e]);
  }
  F r = inv(run);
  for (int e = len - 1; e >= 0; e--) {
    uint64_t i = base + e;
    F di = mul(r, pre[e]);
    r = mul(r, d[e]);
    F zi = load(z, i);
    F zs = load(z, i + 1 == n ? 0 : i + 1);
    F ord = sub(mul(load(p_s, i), zs), mul(load(p_id, i), zi));
    F loc = mul(mul(sub(zi, one()), di), alpha2_l1);
    store(acc, i, add(load(acc, i), add(mul(ord, alpha), loc)));
  }
}

// h[t*n + i] (+)= w[t] * g[i] for t < 3, and h[3n + i] (+)= w[3] * g[i] for i < 8.
__global__ void k_h_accum(void* h, const void* g, uint64_t n, F w0, F w1, F w2, F w3, int init) {
  uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  if (i >= n) return;
  F x = load(g, i);
  F ws[4] = {w0, w1, w2, w3};
  int tmax = i < 8 ? 4 : 3;
  for (int t = 0; t < tmax; t++) {
    F y = mul(x, ws[t]);
    uint64_t idx = t * n + i;
    store(h, idx, init ? y : add(load(h, idx), y));
  }
}

constexpr int RATIO_CHUNK = 8;

__device__ __forceinline__ F id_value(uint32_t p, uint64_t n, const F* tab_w, const F& u, const F& u2) {
  uint64_t k = p / n;
  F w = pow_tab(tab_w, p - k * n);
  return k == 0 ? w : mul(w, k == 1 ? u : u2);
}

// z[i+1] = prod_j (f_j[i] + beta*k_j*w^i + gamma) / prod_j (f_j[i] + beta*id(sigma_j(i)) + gamma), in Montgomery form; z[0] = 1.
__global__ void k_ratio(F* z, const void* l, const void* r, const void* o, const uint32_t* sigma, uint64_t n, const F* tab_w, F beta, F gamma,
                        F u, F u2) {
  uint64_t base = (blockIdx.x * (uint64_t)blockDim.x + threadIdx.x) * RATIO_CHUNK;
  if (base >= n - 1) return;
  if (base == 0) z[0] = one();
  int len = (int)min((uint64_t)RATIO_CHUNK, n - 1 - base);
  F num[RATIO_CHUNK], den[RATIO_CHUNK], pre[RATIO_CHUNK];
  F bu = mul(beta, u), bu2 = mul(beta, u2);
  F run = one();
  for (int e = 0; e < len; e++) {
    uint64_t i = base + e;
    F w = pow_tab(tab_w, i);
    F fl = load(l, i), fr = load(r, i), fo = load(o, i);
    F a = add(add(fl, mul(beta, w)), gamma);
    F b = add(add(fr, mul(bu, w)), gamma);
    F cc = add(add(fo, mul(bu2, w)), gamma);
    num[e] = mul(mul(a, b), cc);
    F da = add(add(fl, mul(beta, id_value(sigma[i], n, tab_w, u, u2))), gamma);
    F db = add(add(fr, mul(beta, id_value(sigma[n + i], n, tab_w, u, u2))), gamma);
    F dc = add(add(fo, mul(beta, id_value(sigma[2 * n + i], n, tab_w, u, u2))), gamma);
    den[e] = mul(mul(da, db), dc);
    pre[e] = run;
    run = mul(run, den[e]);
  }
  F rinv = inv(run);
  for (int e = len - 1; e >= 0; e--) {
    F di = mul(rinv, pre[e]);
    rinv = mul(rinv, den[e]);
    z[base + e + 1] = mul(num[e], di);
  }
}

__global__ void k_sigma_lagrange(void* dst, const uint32_t* sigma, uint64_t n, const F* tab_w, F u, F u2) {
  uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  if (i < n) store(dst, i, id_value(sigma[i], n, tab_w, u, u2));
}

// out[t] = sum_{i in chunk t} p_i z^(i - t*chunk), Montgomery form.
__global__ void k_eval_partials(F* out, const void* p, uint64_t len, F z, uint64_t chunk) {
  uint64_t t = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  uint64_t s = t * chunk;
  if (s >= len) return;
  uint64_t e = min(len, s + chunk);
  F acc = {{0, 0, 0, 0}};
  for (uint64_t i = e; i > s; i--) acc = add(mul(acc, z), load(p, i - 1));
  out[t] = acc;
}

// q_i = f_{i+1} + a q_{i+1}; chunk t starts from carries[t+1] = q_{e_t - 1} and writes q_i for i in [max(s_t - 1, 0), e_t - 2].
__global__ void k_div_xma(void* out, const void* f, uint64_t len, F a, const F* carries, uint64_t chunk) {
  uint64_t t = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  uint64_t s = t * chunk;
  if (s >= len) return;
  uint64_t e = min(len, s + chunk);
  F q = carries[t + 1];
  for (uint64_t i = e - 1; i >= s && i >= 1; i--) {
    q = add(load(f, i), mul(a, q));
    store(out, i - 1, q);
  }
}

__global__ void k_gather(void* dst, const F* src, const uint32_t* idx, uint64_t n) {
  uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  if (i < n) store(dst, i, src[idx[i]]);
}

__global__ void k_scatter(void* dst, const uint32_t* pos, const F* vals, uint64_t cnt) {
  uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  if (i < cnt) store(dst, pos[i], vals[i]);
}

struct LinConsts {
  F s1, s2, rl, lz, rz, oz, qcpz, a2l1, zh, zn2;
};

__global__ void k_linearize(void* out, const void* bz, uint64_t len_bz, const void* s3, const void* ql, const void* qr, const void* qm,
                            const void* qo, const void* qk, const void* pi, uint64_t n, const void* h, uint64_t len_h, LinConsts c) {
  uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
  if (i >= len_bz) return;
  F b = load(bz, i);
  F t = mul(b, c.s2);
  if (i < n) {
    t = add(t, mul(load(s3, i), c.s1));
    t = add(t, mul(load(qm, i), c.rl));
    t = add(t, mul(load(ql, i), c.lz));
    t = add(t, mul(load(qr, i), c.rz));
    t = add(t, mul(load(qo, i), c.oz));
    t = add(t, load(qk, i));
    t = add(t, mul(load(pi, i), c.qcpz));
  }
  t = add(t, mul(b, c.a2l1));
  if (i < len_h) {
    F hh = add(mul(load(h, 2 * len_h + i), c.zn2), load(h, len_h + i));
    hh = mul(add(mul(hh, c.zn2), load(h, i)), c.zh);
    t = sub(t, hh);
  }
  store(out, i, t);
}

}  // namespace

extern "C" {

int sp1_fr_from_mont(void* x, uint64_t n, void* s) {
  k_from_mont<<<blocks(n), THREADS, 0, st(s)>>>((F*)x, n);
  return err();
}

int sp1_fr_scale_pow(void* dst, const void* src, uint64_t n, const void* tab, void* s) {
  k_scale_pow<<<blocks(n), THREADS, 0, st(s)>>>(dst, src, n, (const F*)tab);
  return err();
}

int sp1_fr_mul(void* out, const void* a, const void* b, uint64_t n, void* s) {
  k_mul<<<blocks(n), THREADS, 0, st(s)>>>(out, a, b, n);
  return err();
}

int sp1_fr_fma(void* acc, const void* a, const void* b, uint64_t n, void* s) {
  k_fma<<<blocks(n), THREADS, 0, st(s)>>>(acc, a, b, n);
  return err();
}

int sp1_fr_fma3(void* acc, const void* a, const void* b, const void* c, uint64_t n, void* s) {
  k_fma3<<<blocks(n), THREADS, 0, st(s)>>>(acc, a, b, c, n);
  return err();
}

int sp1_fr_add(void* acc, const void* a, uint64_t n, void* s) {
  k_add<<<blocks(n), THREADS, 0, st(s)>>>(acc, a, n);
  return err();
}

int sp1_fr_sub(void* acc, const void* a, uint64_t n, void* s) {
  k_sub<<<blocks(n), THREADS, 0, st(s)>>>(acc, a, n);
  return err();
}

int sp1_fr_axpy(void* acc, const void* x, const sp1_fr* sc, uint64_t n, void* s) {
  k_axpy<<<blocks(n), THREADS, 0, st(s)>>>(acc, x, cst(sc), n);
  return err();
}

int sp1_fr_blind_coset(void* v, uint64_t n, const void* tab_w, const sp1_fr* c, const sp1_fr* b, int nb, void* s) {
  F z = {{0, 0, 0, 0}};
  k_blind_coset<<<blocks(n), THREADS, 0, st(s)>>>(v, n, (const F*)tab_w, cst(c), cst(&b[0]), nb > 1 ? cst(&b[1]) : z,
                                                   nb > 2 ? cst(&b[2]) : z, nb);
  return err();
}

int sp1_fr_perm_id(void* acc, const void* v, uint64_t n, const void* tab_w, const sp1_fr* kbc, const sp1_fr* gamma, int init, void* s) {
  k_perm_id<<<blocks(n), THREADS, 0, st(s)>>>(acc, v, n, (const F*)tab_w, cst(kbc), cst(gamma), init);
  return err();
}

int sp1_fr_perm_s(void* acc, const void* v, const void* sv, uint64_t n, const sp1_fr* beta, const sp1_fr* gamma, int init, void* s) {
  k_perm_s<<<blocks(n), THREADS, 0, st(s)>>>(acc, v, sv, n, cst(beta), cst(gamma), init);
  return err();
}

int sp1_fr_z_combine(void* acc, const void* p_id, const void* p_s, const void* z, uint64_t n, const void* tab_w, const sp1_fr* c,
                     const sp1_fr* alpha, const sp1_fr* alpha2_l1, void* s) {
  uint64_t threads = (n + ZC_CHUNK - 1) / ZC_CHUNK;
  k_z_combine<<<blocks(threads), THREADS, 0, st(s)>>>(acc, p_id, p_s, z, n, (const F*)tab_w, cst(c), cst(alpha), cst(alpha2_l1));
  return err();
}

int sp1_fr_h_accum(void* h, const void* g, uint64_t n, const sp1_fr* w, int init, void* s) {
  k_h_accum<<<blocks(n), THREADS, 0, st(s)>>>(h, g, n, cst(&w[0]), cst(&w[1]), cst(&w[2]), cst(&w[3]), init);
  return err();
}

int sp1_fr_ratio(void* z, const void* l, const void* r, const void* o, const uint32_t* sigma, uint64_t n, const void* tab_w,
                 const sp1_fr* beta, const sp1_fr* gamma, const sp1_fr* u, const sp1_fr* u2, void* s) {
  uint64_t threads = (n - 1 + RATIO_CHUNK - 1) / RATIO_CHUNK;
  k_ratio<<<blocks(threads), THREADS, 0, st(s)>>>((F*)z, l, r, o, sigma, n, (const F*)tab_w, cst(beta), cst(gamma), cst(u), cst(u2));
  return err();
}

int sp1_fr_scan_mul(void* z, uint64_t n, void* s) {
  F* p = (F*)z;
  size_t tmp_bytes = 0;
  cub::DeviceScan::InclusiveScan(nullptr, tmp_bytes, p, p, MulOp(), (int64_t)n, st(s));
  void* tmp;
  if (cudaMallocAsync(&tmp, tmp_bytes, st(s)) != cudaSuccess) return err();
  cub::DeviceScan::InclusiveScan(tmp, tmp_bytes, p, p, MulOp(), (int64_t)n, st(s));
  cudaFreeAsync(tmp, st(s));
  return err();
}

int sp1_fr_sigma_lagrange(void* dst, const uint32_t* sigma, uint64_t n, const void* tab_w, const sp1_fr* u, const sp1_fr* u2, void* s) {
  k_sigma_lagrange<<<blocks(n), THREADS, 0, st(s)>>>(dst, sigma, n, (const F*)tab_w, cst(u), cst(u2));
  return err();
}

int sp1_fr_eval_partials(sp1_fr* out, const void* p, uint64_t len, const sp1_fr* z, uint64_t chunk, void* s) {
  uint64_t nt = (len + chunk - 1) / chunk;
  F* d;
  if (cudaMallocAsync(&d, nt * sizeof(F), st(s)) != cudaSuccess) return err();
  k_eval_partials<<<blocks(nt), THREADS, 0, st(s)>>>(d, p, len, cst(z), chunk);
  cudaMemcpyAsync(out, d, nt * sizeof(F), cudaMemcpyDeviceToHost, st(s));
  cudaFreeAsync(d, st(s));
  cudaStreamSynchronize(st(s));
  return err();
}

int sp1_fr_div_xma(void* out, const void* f, uint64_t len, const sp1_fr* a, const sp1_fr* carries, uint64_t chunk, void* s) {
  uint64_t nt = (len + chunk - 1) / chunk;
  F* d;
  if (cudaMallocAsync(&d, (nt + 1) * sizeof(F), st(s)) != cudaSuccess) return err();
  cudaMemcpyAsync(d, carries, (nt + 1) * sizeof(F), cudaMemcpyHostToDevice, st(s));
  k_div_xma<<<blocks(nt), THREADS, 0, st(s)>>>(out, f, len, cst(a), d, chunk);
  cudaFreeAsync(d, st(s));
  cudaStreamSynchronize(st(s));
  return err();
}

int sp1_fr_gather(void* dst, const void* src, const uint32_t* idx, uint64_t n, void* s) {
  k_gather<<<blocks(n), THREADS, 0, st(s)>>>(dst, (const F*)src, idx, n);
  return err();
}

int sp1_fr_scatter(void* dst, const uint32_t* pos, const sp1_fr* vals, uint64_t cnt, void* s) {
  F* d;
  if (cudaMallocAsync(&d, cnt * sizeof(F), st(s)) != cudaSuccess) return err();
  cudaMemcpyAsync(d, vals, cnt * sizeof(F), cudaMemcpyHostToDevice, st(s));
  k_scatter<<<blocks(cnt), THREADS, 0, st(s)>>>(dst, pos, d, cnt);
  cudaFreeAsync(d, st(s));
  cudaStreamSynchronize(st(s));
  return err();
}

int sp1_fr_linearize(void* out, const void* bz, uint64_t len_bz, const void* s3, const void* ql, const void* qr, const void* qm, const void* qo,
                     const void* qk, const void* pi, uint64_t n, const void* h, uint64_t len_h, const sp1_fr* consts, void* s) {
  LinConsts c = *reinterpret_cast<const LinConsts*>(consts);
  k_linearize<<<blocks(len_bz), THREADS, 0, st(s)>>>(out, bz, len_bz, s3, ql, qr, qm, qo, qk, pi, n, h, len_h, c);
  return err();
}

int sp1_malloc_host(void** ptr, uint64_t size) { return (int)cudaMallocHost(ptr, size); }

int sp1_memcpy_h2d(void* dst, const void* src, uint64_t size, void* s) {
  return (int)cudaMemcpyAsync(dst, src, size, cudaMemcpyHostToDevice, st(s));
}

int sp1_memcpy_d2h(void* dst, const void* src, uint64_t size, void* s) {
  return (int)cudaMemcpyAsync(dst, src, size, cudaMemcpyDeviceToHost, st(s));
}

int sp1_memset(void* dst, uint64_t size, void* s) { return (int)cudaMemsetAsync(dst, 0, size, st(s)); }

int sp1_sync(void* s) { return (int)cudaStreamSynchronize(st(s)); }

int sp1_stream_create(void** s) { return (int)cudaStreamCreateWithFlags(reinterpret_cast<cudaStream_t*>(s), cudaStreamNonBlocking); }

int sp1_event_create(void** e) { return (int)cudaEventCreateWithFlags(reinterpret_cast<cudaEvent_t*>(e), cudaEventDisableTiming); }

int sp1_event_record(void* e, void* s) { return (int)cudaEventRecord(reinterpret_cast<cudaEvent_t>(e), st(s)); }

int sp1_stream_wait(void* s, void* e) { return (int)cudaStreamWaitEvent(st(s), reinterpret_cast<cudaEvent_t>(e), 0); }
}
