#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Device vectors hold BN254 scalars in standard form, 4 little-endian 64-bit limbs each, as ICICLE expects.
// Scalar arguments passed by pointer are host values in gnark's Montgomery form.
// Power tables hold c^i for i < 2^12 followed by c^(2^12 * i) for i < 2^14, in Montgomery form.

typedef struct {
  uint64_t v[4];
} sp1_fr;

int sp1_fr_from_mont(void* x, uint64_t n, void* stream);
int sp1_fr_scale_pow(void* dst, const void* src, uint64_t n, const void* tab, void* stream);
int sp1_fr_mul(void* out, const void* a, const void* b, uint64_t n, void* stream);
int sp1_fr_fma(void* acc, const void* a, const void* b, uint64_t n, void* stream);
int sp1_fr_fma3(void* acc, const void* a, const void* b, const void* c, uint64_t n, void* stream);
int sp1_fr_add(void* acc, const void* a, uint64_t n, void* stream);
int sp1_fr_sub(void* acc, const void* a, uint64_t n, void* stream);
int sp1_fr_axpy(void* acc, const void* x, const sp1_fr* s, uint64_t n, void* stream);
int sp1_fr_blind_coset(void* v, uint64_t n, const void* tab_w, const sp1_fr* c, const sp1_fr* b, int nb, void* stream);
int sp1_fr_perm_id(void* acc, const void* v, uint64_t n, const void* tab_w, const sp1_fr* kbc, const sp1_fr* gamma, int init, void* stream);
int sp1_fr_perm_s(void* acc, const void* v, const void* s, uint64_t n, const sp1_fr* beta, const sp1_fr* gamma, int init, void* stream);
int sp1_fr_z_combine(void* acc, const void* p_id, const void* p_s, const void* z, uint64_t n, const void* tab_w, const sp1_fr* c, const sp1_fr* alpha, const sp1_fr* alpha2_l1, void* stream);
int sp1_fr_h_accum(void* h, const void* g, uint64_t n, const sp1_fr* w, int init, void* stream);
int sp1_fr_ratio(void* z, const void* l, const void* r, const void* o, const uint32_t* sigma, uint64_t n, const void* tab_w, const sp1_fr* beta, const sp1_fr* gamma, const sp1_fr* u, const sp1_fr* u2, void* stream);
int sp1_fr_scan_mul(void* z, uint64_t n, void* stream);
int sp1_fr_sigma_lagrange(void* dst, const uint32_t* sigma, uint64_t n, const void* tab_w, const sp1_fr* u, const sp1_fr* u2, void* stream);
int sp1_fr_eval_partials(sp1_fr* out, const void* p, uint64_t len, const sp1_fr* z, uint64_t chunk, void* stream);
int sp1_fr_div_xma(void* out, const void* f, uint64_t len, const sp1_fr* a, const sp1_fr* carries, uint64_t chunk, void* stream);
// dst[i] = src[idx[i]] where src holds Montgomery-form values.
int sp1_fr_gather(void* dst, const void* src, const uint32_t* idx, uint64_t n, void* stream);
int sp1_fr_scatter(void* dst, const uint32_t* pos, const sp1_fr* vals, uint64_t cnt, void* stream);
int sp1_fr_linearize(void* out, const void* bz, uint64_t len_bz, const void* s3, const void* ql, const void* qr, const void* qm, const void* qo,
                     const void* qk, const void* pi, uint64_t n, const void* h, uint64_t len_h, const sp1_fr* consts, void* stream);

int sp1_malloc_host(void** ptr, uint64_t size);
int sp1_memcpy_h2d(void* dst, const void* src, uint64_t size, void* stream);
int sp1_memcpy_d2h(void* dst, const void* src, uint64_t size, void* stream);
int sp1_memset(void* dst, uint64_t size, void* stream);
int sp1_sync(void* stream);
int sp1_stream_create(void** stream);
int sp1_event_create(void** event);
int sp1_event_record(void* event, void* stream);
int sp1_stream_wait(void* stream, void* event);

#ifdef __cplusplus
}
#endif
