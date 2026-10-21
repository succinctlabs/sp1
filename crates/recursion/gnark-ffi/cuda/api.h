#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Device vectors hold BN254 field elements in gnark-crypto's layout: Montgomery form, four little-endian
// 64-bit limbs. Points are gnark affine points, with (0, 0) for infinity. Scalar arguments passed by
// pointer are host values in the same form. Power tables hold c^i for i < 2^12 followed by c^(2^12 * i)
// for i < 2^14.

typedef struct {
  uint64_t v[4];
} sp1_fr;

// In-place NTT of size 2^log_n in natural order; tab is the power table of the root of unity used.
// Every output is multiplied by scale when it is not null, which gives the inverse NTT for 1/n.
int sp1_ntt(void* data, uint32_t log_n, const void* tab, const sp1_fr* scale, void* stream);

enum { SP1_SRC_DATA, SP1_SRC_GATHER, SP1_SRC_EXPAND, SP1_SRC_SIGMA };

// Where a DIF NTT reads its input element i from: data[i] (DATA), a[b[i]] with uint32 b (GATHER) or uint16
// b (EXPAND), or the permutation value of b[i] with a the power table of the root of unity and u, u2 the
// coset shifts (SIGMA).
typedef struct {
  int kind;
  const void* a;
  const void* b;
  sp1_fr u, u2;
} sp1_ntt_src;

// In-place DIF NTT: natural-order input, read from src when not null, to bit-reversed output. Every input
// is multiplied by scale when it is not null.
int sp1_ntt_dif(void* data, uint32_t log_n, const void* tab, const sp1_fr* scale, const sp1_ntt_src* src, void* stream);
// In-place DIT NTT: bit-reversed input to natural-order output. When coset_tab is not null, the input of
// index i (at position bitrev(i)) is first multiplied by c^i, c being its base.
int sp1_ntt_dit(void* data, uint32_t log_n, const void* tab, const void* coset_tab, void* stream);
// In-place bit-reversal permutation of 2^log_n elements.
int sp1_bitrev(void* data, uint32_t log_n, void* stream);

// Multi-scalar multiplications with c-bit windows; writes one XYZZ point per window to windows_out
// (host memory), the sum of which, weighted by 2^(c * w), is the result.
int sp1_msm_g1(void* windows_out, uint32_t* nwindows, const void* scalars, const void* points, uint64_t n,
               uint32_t c, void* stream);
int sp1_msm_g2(void* windows_out, uint32_t* nwindows, const void* scalars, const void* points, uint64_t n,
               uint32_t c, void* stream);

int sp1_fr_scale_pow(void* dst, const void* src, uint64_t n, const void* tab, void* stream);
int sp1_fr_mul(void* out, const void* a, const void* b, uint64_t n, void* stream);
int sp1_fr_fma(void* acc, const void* a, const void* b, uint64_t n, void* stream);
int sp1_fr_fma3(void* acc, const void* a, const void* b, const void* c, uint64_t n, void* stream);
int sp1_fr_add(void* acc, const void* a, uint64_t n, void* stream);
int sp1_fr_sub(void* acc, const void* a, uint64_t n, void* stream);
int sp1_fr_axpy(void* acc, const void* x, const sp1_fr* s, uint64_t n, void* stream);
int sp1_fr_scale(void* x, const sp1_fr* s, uint64_t n, void* stream);
int sp1_fr_blind_coset(void* v, uint64_t n, const void* tab_w, const sp1_fr* c, const sp1_fr* b, int nb, void* stream);
int sp1_fr_perm_id(void* acc, const void* v, uint64_t n, const void* tab_w, const sp1_fr* kbc, const sp1_fr* gamma, int init,
                   void* stream);
int sp1_fr_perm_s(void* acc, const void* v, const void* s, uint64_t n, const sp1_fr* beta, const sp1_fr* gamma, int init,
                  void* stream);
int sp1_fr_z_combine(void* acc, const void* p_id, const void* p_s, const void* z, uint64_t n, const void* tab_w,
                     const sp1_fr* c, const sp1_fr* alpha, const sp1_fr* alpha2_l1, void* stream);
// Adds w[t] * c^-i * g[bitrev(i)] to h[t*n + i] for t < 3, and for t = 3 when i < 8; init overwrites h instead.
// ctab_inv is the power table of 1/c.
int sp1_fr_h_accum(void* h, const void* g, uint64_t n, const void* ctab_inv, const sp1_fr* w, int init, void* stream);
// The copy constraint accumulator of the wires values[wires[j*n + i]], in Montgomery form, before its scan.
int sp1_fr_ratio(void* z, const void* values, const uint32_t* wires, const uint32_t* sigma, uint64_t n, const void* tab_w,
                 const sp1_fr* beta, const sp1_fr* gamma, const sp1_fr* u, const sp1_fr* u2, void* stream);
int sp1_fr_scan_mul(void* z, uint64_t n, void* stream);
int sp1_fr_eval_partials(sp1_fr* out, const void* p, uint64_t len, const sp1_fr* z, uint64_t chunk, void* stream);
int sp1_fr_div_xma(void* out, const void* f, uint64_t len, const sp1_fr* a, const sp1_fr* carries, uint64_t chunk,
                   void* stream);
// dst[pos[i]] = vals[i], with vals in host memory.
int sp1_fr_scatter(void* dst, const uint32_t* pos, const sp1_fr* vals, uint64_t cnt, void* stream);
// dst[i] = table[idx[i]], with table in host memory.
int sp1_fr_expand(void* dst, const uint16_t* idx, const sp1_fr* table, uint32_t table_len, uint64_t n, void* stream);

int sp1_malloc(void** ptr, uint64_t size, void* stream);
int sp1_free(void* ptr, void* stream);
int sp1_host_register(void* ptr, uint64_t size);
int sp1_memcpy_h2d(void* dst, const void* src, uint64_t size, void* stream);
int sp1_memcpy_d2h(void* dst, const void* src, uint64_t size, void* stream);
int sp1_memset(void* dst, uint64_t size, void* stream);
int sp1_sync(void* stream);
int sp1_stream_create(void** stream);
int sp1_event_create(void** event);
int sp1_event_record(void* event, void* stream);
int sp1_stream_wait(void* stream, void* event);
// Releases the memory cached by the device's default pool, such as the SP1 GPU prover's, so that
// cudaMalloc can use it.
int sp1_trim_pool(void);

#ifdef __cplusplus
}
#endif
