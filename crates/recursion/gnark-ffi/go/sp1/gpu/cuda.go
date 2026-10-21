//go:build cuda

package gpu

// #cgo CFLAGS: -I${SRCDIR}/../../../cuda
// #cgo LDFLAGS: -lsp1gpu -lcudart -lstdc++
// #include "api.h"
import "C"

import (
	"fmt"
	"sync"
	"unsafe"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// dvec is a device buffer of n elements.
type dvec struct {
	p unsafe.Pointer
	n int
}

// at returns the sub-buffer starting at element i, for elements of the given size.
func (d dvec) at(i, size int) dvec {
	return dvec{unsafe.Add(d.p, i*size), d.n - i}
}

func (d dvec) fr(i int) dvec { return d.at(i, fr.Bytes) }

func check(code C.int, op string) {
	if code != 0 {
		panic(fmt.Sprintf("gpu: %s failed with CUDA error %d", op, int(code)))
	}
}

func cfr(x *fr.Element) *C.sp1_fr { return (*C.sp1_fr)(unsafe.Pointer(x)) }

func cbool(b bool) C.int {
	if b {
		return 1
	}
	return 0
}

// live tracks device allocations, so that a failed proof does not leak them.
var live = struct {
	sync.Mutex
	m map[unsafe.Pointer]struct{}
}{m: map[unsafe.Pointer]struct{}{}}

func allocBytes(size, n int) dvec {
	var p unsafe.Pointer
	check(C.sp1_malloc(&p, C.uint64_t(size), nil), fmt.Sprintf("malloc of %d bytes", size))
	live.Lock()
	live.m[p] = struct{}{}
	live.Unlock()
	return dvec{p, n}
}

func alloc(n int) dvec { return allocBytes(n*fr.Bytes, n) }

func (d dvec) free() {
	live.Lock()
	delete(live.m, d.p)
	live.Unlock()
	check(C.sp1_free(d.p, nil), "free")
}

// freeAll frees every live device allocation.
func freeAll() {
	live.Lock()
	defer live.Unlock()
	for p := range live.m {
		C.sp1_free(p, nil)
		delete(live.m, p)
	}
	C.sp1_sync(nil)
}

func upload[T any](v []T) dvec {
	d := allocBytes(len(v)*int(unsafe.Sizeof(v[0])), len(v))
	h2d(d, unsafe.Pointer(&v[0]), len(v)*int(unsafe.Sizeof(v[0])))
	return d
}

func h2dElements(dst dvec, src []fr.Element) {
	h2d(dst, unsafe.Pointer(&src[0]), len(src)*fr.Bytes)
}

func h2d(dst dvec, src unsafe.Pointer, size int) {
	check(C.sp1_memcpy_h2d(dst.p, src, C.uint64_t(size), nil), "memcpy_h2d")
}

func h2dAsync(dst dvec, src unsafe.Pointer, size int, stream unsafe.Pointer) {
	check(C.sp1_memcpy_h2d(dst.p, src, C.uint64_t(size), stream), "memcpy_h2d")
}

func d2h(dst unsafe.Pointer, src dvec, size int) {
	check(C.sp1_memcpy_d2h(dst, src.p, C.uint64_t(size), nil), "memcpy_d2h")
}

func d2hAsync(dst unsafe.Pointer, src dvec, size int, stream unsafe.Pointer) {
	check(C.sp1_memcpy_d2h(dst, src.p, C.uint64_t(size), stream), "memcpy_d2h")
}

func memset0(d dvec, size int) {
	check(C.sp1_memset(d.p, C.uint64_t(size), nil), "memset")
}

func deviceSync() { check(C.sp1_sync(nil), "sync") }

func syncStream(s unsafe.Pointer) { check(C.sp1_sync(s), "sync") }

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

// pin page-locks host memory so that it can be copied asynchronously and at full bandwidth.
func pin[T any](v []T) {
	check(C.sp1_host_register(unsafe.Pointer(&v[0]), C.uint64_t(len(v)*int(unsafe.Sizeof(v[0])))), "host_register")
}

// TrimPool releases the memory cached by the device's default pool, which the SP1 GPU prover
// allocates from, so that the provers here can use it.
func TrimPool() { C.sp1_trim_pool() }

func bitrev(v dvec, logN int) { check(C.sp1_bitrev(v.p, C.uint32_t(logN), nil), "bitrev") }

func ntt(v dvec, logN int, tab dvec, scale *fr.Element) {
	var s *C.sp1_fr
	if scale != nil {
		s = cfr(scale)
	}
	check(C.sp1_ntt(v.p, C.uint32_t(logN), tab.p, s, nil), "ntt")
}

// nttSrc is where nttDIF reads its input from; nil reads the vector itself.
type nttSrc = C.sp1_ntt_src

func srcGather(values, idx dvec) *nttSrc {
	return &nttSrc{kind: C.SP1_SRC_GATHER, a: values.p, b: idx.p}
}

func srcExpand(table, idx dvec) *nttSrc {
	return &nttSrc{kind: C.SP1_SRC_EXPAND, a: table.p, b: idx.p}
}

func srcSigma(sigma, tabW dvec, u, u2 fr.Element) *nttSrc {
	return &nttSrc{kind: C.SP1_SRC_SIGMA, a: tabW.p, b: sigma.p, u: *cfr(&u), u2: *cfr(&u2)}
}

// nttDIF transforms natural-order input into bit-reversed output.
func nttDIF(v dvec, logN int, tab dvec, scale *fr.Element, src *nttSrc) {
	var s *C.sp1_fr
	if scale != nil {
		s = cfr(scale)
	}
	check(C.sp1_ntt_dif(v.p, C.uint32_t(logN), tab.p, s, src, nil), "ntt_dif")
}

// nttDIT transforms bit-reversed input into natural-order output, evaluating on a coset when coset is set.
func nttDIT(v dvec, logN int, tab, coset dvec) {
	check(C.sp1_ntt_dit(v.p, C.uint32_t(logN), tab.p, coset.p, nil), "ntt_dit")
}

func scalePow(dst, src dvec, n int, tab dvec) {
	check(C.sp1_fr_scale_pow(dst.p, src.p, C.uint64_t(n), tab.p, nil), "scale_pow")
}

func vmul(out, a, b dvec, n int) { check(C.sp1_fr_mul(out.p, a.p, b.p, C.uint64_t(n), nil), "mul") }

func vfma(acc, a, b dvec, n int) { check(C.sp1_fr_fma(acc.p, a.p, b.p, C.uint64_t(n), nil), "fma") }

func vfma3(acc, a, b, c dvec, n int) {
	check(C.sp1_fr_fma3(acc.p, a.p, b.p, c.p, C.uint64_t(n), nil), "fma3")
}

func vadd(acc, a dvec, n int) { check(C.sp1_fr_add(acc.p, a.p, C.uint64_t(n), nil), "add") }

func vsub(acc, a dvec, n int) { check(C.sp1_fr_sub(acc.p, a.p, C.uint64_t(n), nil), "sub") }

func axpy(acc, x dvec, s fr.Element, n int) {
	check(C.sp1_fr_axpy(acc.p, x.p, cfr(&s), C.uint64_t(n), nil), "axpy")
}

func vscale(x dvec, s fr.Element, n int) {
	check(C.sp1_fr_scale(x.p, cfr(&s), C.uint64_t(n), nil), "scale")
}

func blindCoset(v dvec, n int, tabW dvec, c fr.Element, b []fr.Element) {
	check(C.sp1_fr_blind_coset(v.p, C.uint64_t(n), tabW.p, cfr(&c), cfr(&b[0]), C.int(len(b)), nil), "blind_coset")
}

func permID(acc, v dvec, n int, tabW dvec, kbc, gamma fr.Element, init bool) {
	check(C.sp1_fr_perm_id(acc.p, v.p, C.uint64_t(n), tabW.p, cfr(&kbc), cfr(&gamma), cbool(init), nil), "perm_id")
}

func permS(acc, v, s dvec, n int, beta, gamma fr.Element, init bool) {
	check(C.sp1_fr_perm_s(acc.p, v.p, s.p, C.uint64_t(n), cfr(&beta), cfr(&gamma), cbool(init), nil), "perm_s")
}

func zCombine(acc, pID, pS, z dvec, n int, tabW dvec, c, alpha, alpha2L1 fr.Element) {
	check(C.sp1_fr_z_combine(acc.p, pID.p, pS.p, z.p, C.uint64_t(n), tabW.p, cfr(&c), cfr(&alpha), cfr(&alpha2L1), nil),
		"z_combine")
}

func hAccum(h, g dvec, n int, cInv dvec, w [4]fr.Element, init bool) {
	check(C.sp1_fr_h_accum(h.p, g.p, C.uint64_t(n), cInv.p, cfr(&w[0]), cbool(init), nil), "h_accum")
}

func ratio(z, values, wires, sigma dvec, n int, tabW dvec, beta, gamma, u, u2 fr.Element) {
	check(C.sp1_fr_ratio(z.p, values.p, (*C.uint32_t)(wires.p), (*C.uint32_t)(sigma.p), C.uint64_t(n), tabW.p,
		cfr(&beta), cfr(&gamma), cfr(&u), cfr(&u2), nil), "ratio")
}

func scanMul(z dvec, n int) { check(C.sp1_fr_scan_mul(z.p, C.uint64_t(n), nil), "scan_mul") }

func evalPartials(p dvec, n int, z fr.Element, chunk int) []fr.Element {
	out := make([]fr.Element, (n+chunk-1)/chunk)
	check(C.sp1_fr_eval_partials(cfr(&out[0]), p.p, C.uint64_t(n), cfr(&z), C.uint64_t(chunk), nil), "eval_partials")
	return out
}

func divXMinusA(out, f dvec, n int, a fr.Element, carries []fr.Element, chunk int) {
	check(C.sp1_fr_div_xma(out.p, f.p, C.uint64_t(n), cfr(&a), cfr(&carries[0]), C.uint64_t(chunk), nil), "div_xma")
}

func scatter(dst, pos dvec, vals []fr.Element) {
	check(C.sp1_fr_scatter(dst.p, (*C.uint32_t)(pos.p), cfr(&vals[0]), C.uint64_t(len(vals)), nil), "scatter")
}

func expand(dst, idx dvec, table []fr.Element, n int) {
	check(C.sp1_fr_expand(dst.p, (*C.uint16_t)(idx.p), cfr(&table[0]), C.uint32_t(len(table)), C.uint64_t(n), nil),
		"expand")
}

// The MSM kernels return one point per window in extended Jacobian coordinates.
type xyzz struct{ X, Y, ZZ, ZZZ fp.Element }
type xyzzG2 struct{ X, Y, ZZ, ZZZ curve.E2 }

const msmWindow = 16

// msm returns sum_i scalars[i] * points[i] for n device-resident scalars and points.
func msm(scalars, points dvec, n int) curve.G1Affine {
	var windows [32]xyzz
	var nw C.uint32_t
	check(C.sp1_msm_g1(unsafe.Pointer(&windows[0]), &nw, scalars.p, points.p, C.uint64_t(n), msmWindow, nil), "msm")
	var acc curve.G1Jac
	for i := int(nw) - 1; i >= 0; i-- {
		for k := 0; k < msmWindow; k++ {
			acc.DoubleAssign()
		}
		if w := windows[i]; !w.ZZ.IsZero() {
			var zzInv, zzzInv fp.Element
			zzInv.Inverse(&w.ZZ)
			zzzInv.Inverse(&w.ZZZ)
			var a curve.G1Affine
			a.X.Mul(&w.X, &zzInv)
			a.Y.Mul(&w.Y, &zzzInv)
			acc.AddMixed(&a)
		}
	}
	var r curve.G1Affine
	r.FromJacobian(&acc)
	return r
}

func msmG2(scalars, points dvec, n int) curve.G2Affine {
	var windows [32]xyzzG2
	var nw C.uint32_t
	check(C.sp1_msm_g2(unsafe.Pointer(&windows[0]), &nw, scalars.p, points.p, C.uint64_t(n), msmWindow, nil), "msm_g2")
	var acc curve.G2Jac
	for i := int(nw) - 1; i >= 0; i-- {
		for k := 0; k < msmWindow; k++ {
			acc.DoubleAssign()
		}
		if w := windows[i]; !w.ZZ.IsZero() {
			var zzInv, zzzInv curve.E2
			zzInv.Inverse(&w.ZZ)
			zzzInv.Inverse(&w.ZZZ)
			var a curve.G2Affine
			a.X.Mul(&w.X, &zzInv)
			a.Y.Mul(&w.Y, &zzzInv)
			acc.AddMixed(&a)
		}
	}
	var r curve.G2Affine
	r.FromJacobian(&acc)
	return r
}

// msmHost is msm for host-resident points and scalars, which are uploaded for the call.
func msmHost(points []curve.G1Affine, scalars []fr.Element) curve.G1Affine {
	if len(scalars) == 0 {
		return curve.G1Affine{}
	}
	dp, ds := upload(points[:len(scalars)]), upload(scalars)
	defer dp.free()
	defer ds.free()
	return msm(ds, dp, len(scalars))
}

func msmHostG2(points []curve.G2Affine, scalars []fr.Element) curve.G2Affine {
	if len(scalars) == 0 {
		return curve.G2Affine{}
	}
	dp, ds := upload(points[:len(scalars)]), upload(scalars)
	defer dp.free()
	defer ds.free()
	return msmG2(ds, dp, len(scalars))
}
