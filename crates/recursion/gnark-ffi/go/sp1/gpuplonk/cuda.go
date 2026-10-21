//go:build plonkcuda

package gpuplonk

// #cgo CFLAGS: -I${SRCDIR}/../../../cuda
// #cgo LDFLAGS: -lsp1plonk -lcudart -lstdc++
// #include "plonk.h"
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	icicle_core "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/core"
)

type dvec = icicle_core.DeviceSlice

func ptr(v dvec) unsafe.Pointer { return v.AsUnsafePointer() }

func cfr(x *fr.Element) *C.sp1_fr { return (*C.sp1_fr)(unsafe.Pointer(x)) }

func check(code C.int, op string) {
	if code != 0 {
		panic(fmt.Sprintf("gpuplonk: %s failed with CUDA error %d", op, int(code)))
	}
}

func fromMont(x dvec, n int) {
	check(C.sp1_fr_from_mont(ptr(x), C.uint64_t(n), nil), "from_mont")
}

func scalePow(dst, src dvec, n int, tab dvec) {
	check(C.sp1_fr_scale_pow(ptr(dst), ptr(src), C.uint64_t(n), ptr(tab), nil), "scale_pow")
}

func vmul(out, a, b dvec, n int) {
	check(C.sp1_fr_mul(ptr(out), ptr(a), ptr(b), C.uint64_t(n), nil), "mul")
}

func vfma(acc, a, b dvec, n int) {
	check(C.sp1_fr_fma(ptr(acc), ptr(a), ptr(b), C.uint64_t(n), nil), "fma")
}

func vfma3(acc, a, b, c dvec, n int) {
	check(C.sp1_fr_fma3(ptr(acc), ptr(a), ptr(b), ptr(c), C.uint64_t(n), nil), "fma3")
}

func vadd(acc, a dvec, n int) {
	check(C.sp1_fr_add(ptr(acc), ptr(a), C.uint64_t(n), nil), "add")
}

func vsub(acc, a dvec, n int) {
	check(C.sp1_fr_sub(ptr(acc), ptr(a), C.uint64_t(n), nil), "sub")
}

func axpy(acc, x dvec, s fr.Element, n int) {
	check(C.sp1_fr_axpy(ptr(acc), ptr(x), cfr(&s), C.uint64_t(n), nil), "axpy")
}

func blindCoset(v dvec, n int, tabW dvec, c fr.Element, b []fr.Element) {
	check(C.sp1_fr_blind_coset(ptr(v), C.uint64_t(n), ptr(tabW), cfr(&c), cfr(&b[0]), C.int(len(b)), nil), "blind_coset")
}

func permID(acc, v dvec, n int, tabW dvec, kbc, gamma fr.Element, init bool) {
	check(C.sp1_fr_perm_id(ptr(acc), ptr(v), C.uint64_t(n), ptr(tabW), cfr(&kbc), cfr(&gamma), cbool(init), nil), "perm_id")
}

func permS(acc, v, s dvec, n int, beta, gamma fr.Element, init bool) {
	check(C.sp1_fr_perm_s(ptr(acc), ptr(v), ptr(s), C.uint64_t(n), cfr(&beta), cfr(&gamma), cbool(init), nil), "perm_s")
}

func zCombine(acc, pID, pS, z dvec, n int, tabW dvec, c, alpha, alpha2L1 fr.Element) {
	check(C.sp1_fr_z_combine(ptr(acc), ptr(pID), ptr(pS), ptr(z), C.uint64_t(n), ptr(tabW), cfr(&c), cfr(&alpha), cfr(&alpha2L1), nil), "z_combine")
}

func hAccum(h, g dvec, n int, w [4]fr.Element, init bool) {
	check(C.sp1_fr_h_accum(ptr(h), ptr(g), C.uint64_t(n), cfr(&w[0]), cbool(init), nil), "h_accum")
}

func ratio(z, l, r, o, sigma dvec, n int, tabW dvec, beta, gamma, u, u2 fr.Element) {
	check(C.sp1_fr_ratio(ptr(z), ptr(l), ptr(r), ptr(o), (*C.uint32_t)(ptr(sigma)), C.uint64_t(n), ptr(tabW), cfr(&beta), cfr(&gamma), cfr(&u), cfr(&u2), nil), "ratio")
}

func scanMul(z dvec, n int) {
	check(C.sp1_fr_scan_mul(ptr(z), C.uint64_t(n), nil), "scan_mul")
}

func sigmaLagrange(dst, sigma dvec, n int, tabW dvec, u, u2 fr.Element) {
	check(C.sp1_fr_sigma_lagrange(ptr(dst), (*C.uint32_t)(ptr(sigma)), C.uint64_t(n), ptr(tabW), cfr(&u), cfr(&u2), nil), "sigma_lagrange")
}

func evalPartials(p dvec, n int, z fr.Element, chunk int) []fr.Element {
	out := make([]fr.Element, (n+chunk-1)/chunk)
	check(C.sp1_fr_eval_partials(cfr(&out[0]), ptr(p), C.uint64_t(n), cfr(&z), C.uint64_t(chunk), nil), "eval_partials")
	return out
}

func divXMinusA(out, f dvec, n int, a fr.Element, carries []fr.Element, chunk int) {
	check(C.sp1_fr_div_xma(ptr(out), ptr(f), C.uint64_t(n), cfr(&a), cfr(&carries[0]), C.uint64_t(chunk), nil), "div_xma")
}

func gather(dst, src, idx dvec, n int) {
	check(C.sp1_fr_gather(ptr(dst), ptr(src), (*C.uint32_t)(ptr(idx)), C.uint64_t(n), nil), "gather")
}

func scatter(dst, pos dvec, vals []fr.Element) {
	check(C.sp1_fr_scatter(ptr(dst), (*C.uint32_t)(ptr(pos)), cfr(&vals[0]), C.uint64_t(len(vals)), nil), "scatter")
}

func linearize(out, bz dvec, lenBz int, s3, ql, qr, qm, qo, qk, pi dvec, n int, h dvec, lenH int, consts *[10]fr.Element) {
	check(C.sp1_fr_linearize(ptr(out), ptr(bz), C.uint64_t(lenBz), ptr(s3), ptr(ql), ptr(qr), ptr(qm), ptr(qo), ptr(qk), ptr(pi),
		C.uint64_t(n), ptr(h), C.uint64_t(lenH), cfr(&consts[0]), nil), "linearize")
}

func mallocHost(size int) unsafe.Pointer {
	var p unsafe.Pointer
	check(C.sp1_malloc_host(&p, C.uint64_t(size)), "malloc_host")
	return p
}

func h2d(dst dvec, src unsafe.Pointer, size int) {
	check(C.sp1_memcpy_h2d(ptr(dst), src, C.uint64_t(size), nil), "memcpy_h2d")
}

func d2h(dst unsafe.Pointer, src dvec, size int) {
	check(C.sp1_memcpy_d2h(dst, ptr(src), C.uint64_t(size), nil), "memcpy_d2h")
}

func d2hAsync(dst unsafe.Pointer, src dvec, size int, stream unsafe.Pointer) {
	check(C.sp1_memcpy_d2h(dst, ptr(src), C.uint64_t(size), stream), "memcpy_d2h_async")
}

func newStream() unsafe.Pointer {
	var s unsafe.Pointer
	check(C.sp1_stream_create(&s), "stream_create")
	return s
}

func newEvent() unsafe.Pointer {
	var e unsafe.Pointer
	check(C.sp1_event_create(&e), "event_create")
	return e
}

// after makes work subsequently queued on stream wait for the work queued so far on from.
func after(stream, from, event unsafe.Pointer) {
	check(C.sp1_event_record(event, from), "event_record")
	check(C.sp1_stream_wait(stream, event), "stream_wait")
}

func syncStream(s unsafe.Pointer) {
	check(C.sp1_sync(s), "sync")
}

func memset0(dst dvec, size int) {
	check(C.sp1_memset(ptr(dst), C.uint64_t(size), nil), "memset")
}

func deviceSync() {
	check(C.sp1_sync(nil), "sync")
}

func cbool(b bool) C.int {
	if b {
		return 1
	}
	return 0
}
