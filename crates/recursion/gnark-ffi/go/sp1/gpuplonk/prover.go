//go:build plonkcuda

// Package gpuplonk is a CUDA implementation of gnark's BN254 PLONK prover. It produces proofs for the
// same proving key, transcript and verifier as backend/plonk/bn254.
package gpuplonk

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"sync"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/hash_to_field"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	fcs "github.com/consensys/gnark/frontend/cs"
	icicle_core "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/core"
	icicle_bn254 "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/curves/bn254"
	icicle_msm "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/curves/bn254/msm"
	icicle_ntt "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/curves/bn254/ntt"
	icicle_runtime "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
	"github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime/config_extension"
)

const (
	msmWindow = 15
	msmChunks = 64
	evalChunk = 256
	tabLo     = 1 << 12
	tabHi     = 1 << 14
)

// Prover holds the device-resident proving key of one circuit.
type Prover struct {
	spr     *cs.SparseR1CS
	vk      *plonk_bn254.VerifyingKey
	device  icicle_runtime.Device
	n       int
	nbPub   int
	domain0 *fft.Domain
	u, u2   fr.Element
	cosets  [4]fr.Element
	commit  constraint.PlonkCommitment
	// srsLo and srsHi are the canonical SRS points used to commit to blinding terms b*(X^n - 1).
	srsLo, srsHi []curve.G1Affine
	qkPos        []int
	qkTrace      []fr.Element

	srs                dvec
	srsHost            unsafe.Pointer
	ql, qr, qm, qo, qk dvec
	qcp                dvec
	sigma              dvec
	tabW               dvec
	tabC, tabCInv      [4]dvec
	qcpPos, piPos      dvec
	lroWires           [3]dvec
	solver             *levelSolver
	piPosHost          []uint32
	bsbPoints          dvec
	hostG              [3]unsafe.Pointer
	copyStream         unsafe.Pointer
	computeDone        unsafe.Pointer
	copyDone           unsafe.Pointer
}

var initDomainOnce sync.Once

// NewProver uploads the circuit's proving key to the GPU.
func NewProver(spr *cs.SparseR1CS, pk *plonk_bn254.ProvingKey) (*Prover, error) {
	if os.Getenv("ICICLE_BACKEND_INSTALL_DIR") == "" {
		os.Setenv("ICICLE_BACKEND_INSTALL_DIR", "/usr/local/lib/backend")
	}
	if e := icicle_runtime.LoadBackendFromEnvOrDefault(); e != icicle_runtime.Success {
		return nil, fmt.Errorf("load icicle backend: %s", e.AsString())
	}
	commitments := spr.CommitmentInfo.(constraint.PlonkCommitments)
	if len(commitments) != 1 {
		return nil, fmt.Errorf("gpuplonk supports exactly one bsb22 commitment, got %d", len(commitments))
	}
	p := &Prover{spr: spr, vk: pk.Vk, device: icicle_runtime.CreateDevice("CUDA", 0), commit: commitments[0]}
	sizeSystem := uint64(spr.GetNbConstraints() + len(spr.Public))
	p.domain0 = fft.NewDomain(sizeSystem)
	domain1 := fft.NewDomain(4*sizeSystem, fft.WithoutPrecompute())
	if domain1.Cardinality != 4*p.domain0.Cardinality {
		return nil, fmt.Errorf("gpuplonk expects a quotient domain of 4n")
	}
	if !domain1.FrMultiplicativeGen.Equal(&pk.Vk.CosetShift) || !p.domain0.Generator.Equal(&pk.Vk.Generator) {
		return nil, fmt.Errorf("gpuplonk: proving key domain mismatch")
	}
	p.n = int(p.domain0.Cardinality)
	p.nbPub = len(spr.Public)
	p.u = pk.Vk.CosetShift
	p.u2.Square(&p.u)
	p.cosets[0] = p.u
	for k := 1; k < 4; k++ {
		p.cosets[k].Mul(&p.cosets[k-1], &domain1.Generator)
	}

	n := p.n
	p.srsLo = append([]curve.G1Affine{}, pk.Kzg.G1[:3]...)
	p.srsHi = append([]curve.G1Affine{}, pk.Kzg.G1[n:n+3]...)

	trace := plonk_bn254.NewTrace(spr, p.domain0)
	p.solver = newSolver(spr)
	wires := lroWires(spr, n)
	for i := 0; i < p.nbPub; i++ {
		p.qkPos = append(p.qkPos, i)
	}
	p.qkPos = append(p.qkPos, p.nbPub+p.commit.CommitmentIndex)
	for _, pos := range p.qkPos {
		p.qkTrace = append(p.qkTrace, trace.Qk.Coefficients()[pos])
	}

	var err error
	runOnDevice(&p.device, func() {
		err = p.setupDevice(pk, trace)
		for k := range wires {
			p.lroWires[k] = uploadU32(wires[k])
		}
	})
	return p, err
}

func (p *Prover) setupDevice(pk *plonk_bn254.ProvingKey, trace *plonk_bn254.Trace) error {
	n := p.n
	initDomainOnce.Do(func() {
		g := p.domain0.Generator
		var rou icicle_bn254.ScalarField
		bits := g.Bits()
		rou.FromLimbs(icicle_core.ConvertUint64ArrToUint32Arr(bits[:]))
		if e := icicle_ntt.InitDomain(rou, icicle_core.GetDefaultNTTInitDomainConfig()); e != icicle_runtime.Success {
			panic(fmt.Sprintf("init ntt domain: %s", e.AsString()))
		}
	})

	p.tabW = uploadTab(p.domain0.Generator)
	for k := 0; k < 4; k++ {
		var inv fr.Element
		inv.Inverse(&p.cosets[k])
		p.tabC[k] = uploadTab(p.cosets[k])
		p.tabCInv[k] = uploadTab(inv)
	}

	for _, s := range []struct {
		dst *dvec
		src []fr.Element
	}{
		{&p.ql, trace.Ql.Coefficients()}, {&p.qr, trace.Qr.Coefficients()}, {&p.qm, trace.Qm.Coefficients()},
		{&p.qo, trace.Qo.Coefficients()}, {&p.qk, trace.Qk.Coefficients()}, {&p.qcp, trace.Qcp[0].Coefficients()},
	} {
		*s.dst = uploadFr(s.src)
		ntt(*s.dst, n, icicle_core.KInverse)
	}

	sigma := make([]uint32, len(trace.S))
	for i, s := range trace.S {
		sigma[i] = uint32(s)
	}
	p.sigma = uploadU32(sigma)

	offset := uint32(p.nbPub)
	p.piPosHost = make([]uint32, 0, len(p.commit.Committed)+2)
	for _, c := range p.commit.Committed {
		p.piPosHost = append(p.piPosHost, offset+uint32(c))
	}
	p.qcpPos = uploadU32(p.piPosHost)
	p.piPosHost = append(p.piPosHost, offset+uint32(p.commit.CommitmentIndex), offset+uint32(p.spr.GetNbConstraints()-1))
	p.piPos = uploadU32(p.piPosHost)

	bsb := make([]curve.G1Affine, len(p.piPosHost))
	for i, pos := range p.piPosHost {
		bsb[i] = pk.KzgLagrange.G1[pos]
	}
	p.bsbPoints = uploadPoints(bsb)
	p.srsHost = mallocHost(srsBytes(n))
	pointsToStd(unsafe.Slice((*curve.G1Affine)(p.srsHost), n+3), pk.Kzg.G1[:n+3])
	p.uploadSrs()

	for k := range p.hostG {
		p.hostG[k] = mallocHost(n * fr.Bytes)
	}
	p.copyStream = newStream()
	p.computeDone = newEvent()
	p.copyDone = newEvent()
	deviceSync()
	return nil
}

// Prove computes a PLONK proof for the given full witness: the public inputs, then the secret ones.
func (p *Prover) Prove(fullWitness fr.Vector) (proof *plonk_bn254.Proof, err error) {
	runOnDevice(&p.device, func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("gpuplonk: %v", r)
			}
		}()
		proof, err = p.prove(fullWitness)
	})
	return proof, err
}

type blinding struct {
	l, r, o, z []fr.Element
}

func randomPoly(deg int) []fr.Element {
	a := make([]fr.Element, deg+1)
	for i := range a {
		a[i].SetRandom()
	}
	return a
}

func (p *Prover) prove(wWitness fr.Vector) (*plonk_bn254.Proof, error) {
	n := p.n
	proof := &plonk_bn254.Proof{Bsb22Commitments: make([]kzg.Digest, 1)}
	bp := blinding{l: randomPoly(1), r: randomPoly(1), o: randomPoly(1), z: randomPoly(2)}

	public := wWitness[:p.nbPub]

	// Solve, computing the bsb22 commitment on the GPU.
	var piVals []fr.Element
	var commitmentVal fr.Element
	htf := hash_to_field.New([]byte("BSB22-Plonk"))
	hint := solver.OverrideHint(solver.GetHintID(fcs.Bsb22CommitmentComputePlaceholder), func(_ *big.Int, ins, outs []*big.Int) error {
		ins = ins[1:]
		piVals = make([]fr.Element, len(p.piPosHost))
		for i := range ins {
			piVals[i].SetBigInt(ins[i])
		}
		piVals[len(ins)].SetRandom()
		piVals[len(ins)+1].SetRandom()
		var c curve.G1Affine
		runOnDevice(&p.device, func() {
			c = msmHost(piVals, p.bsbPoints)
		})
		proof.Bsb22Commitments[0] = c
		htf.Write(c.Marshal())
		hashBts := htf.Sum(nil)
		htf.Reset()
		nbBuf := fr.Bytes
		if htf.Size() < fr.Bytes {
			nbBuf = htf.Size()
		}
		commitmentVal.SetBytes(hashBts[:nbBuf])
		commitmentVal.BigInt(outs[0])
		return nil
	})
	if err := p.solver.solve(wWitness, hint); err != nil {
		return nil, err
	}

	// L, R, O: Lagrange on device, canonical copies, commitments.
	values := alloc(len(p.solver.values))
	h2d(values, unsafe.Pointer(&p.solver.values[0]), len(p.solver.values)*fr.Bytes)
	var lag, can [3]dvec
	for i := range lag {
		lag[i] = alloc(n)
		gather(lag[i], values, p.lroWires[i], n)
	}
	values.Free()
	for i := range lag {
		can[i] = alloc(n)
		nttTo(can[i], lag[i], n, icicle_core.KInverse)
	}
	for i, b := range [][]fr.Element{bp.l, bp.r, bp.o} {
		proof.LRO[i] = p.commitBlinded(can[i], b)
	}
	// Pi (bsb22 committed values) in canonical form.
	pi := alloc(n)
	memset0(pi, n*fr.Bytes)
	scatter(pi, p.piPos, piVals)
	ntt(pi, n, icicle_core.KInverse)

	// Transcript: gamma, beta.
	fs := fiatshamir.NewTranscript(sha256.New(), "gamma", "beta", "alpha", "zeta")
	if err := bindPublicData(fs, "gamma", p.vk, public); err != nil {
		return nil, err
	}
	gamma, err := deriveRandomness(fs, "gamma", &proof.LRO[0], &proof.LRO[1], &proof.LRO[2])
	if err != nil {
		return nil, err
	}
	bbeta, err := fs.ComputeChallenge("beta")
	if err != nil {
		return nil, err
	}
	var beta fr.Element
	beta.SetBytes(bbeta)

	// Z, the copy constraint accumulator.
	z := alloc(n + 3)
	ratio(z, lag[0], lag[1], lag[2], p.sigma, n, p.tabW, beta, gamma, p.u, p.u2)
	scanMul(z, n)
	fromMont(z, n)
	for i := range lag {
		lag[i].Free()
	}
	ntt(z, n, icicle_core.KInverse)
	proof.Z = p.commitBlinded(z, bp.z)

	alpha, err := deriveRandomness(fs, "alpha", &proof.Bsb22Commitments[0], &proof.Z)
	if err != nil {
		return nil, err
	}

	// The SRS leaves the device while the quotient needs the memory.
	p.srs.Free()
	h := func() dvec {
		defer p.uploadSrs()
		return p.quotient(can, z, pi, bp, public, commitmentVal, alpha, beta, gamma)
	}()

	np2 := n + 2
	for i := 0; i < 3; i++ {
		proof.H[i] = msm(h.Range(i*np2, (i+1)*np2, false), p.srs.Range(0, np2, false))
	}

	zeta, err := deriveRandomness(fs, "zeta", &proof.H[0], &proof.H[1], &proof.H[2])
	if err != nil {
		return nil, err
	}

	// Open Z (blinded) at zeta * omega.
	var zetaShifted fr.Element
	zetaShifted.Mul(&zeta, &p.vk.Generator)
	p.blindCoefficients(z, n, bp.z)
	proof.ZShiftedOpening.ClaimedValue, proof.ZShiftedOpening.H = p.open(z, n+3, zetaShifted)

	// Evaluations at zeta.
	var zetaN, zhZeta, one fr.Element
	one.SetOne()
	zetaN.Exp(zeta, big.NewInt(int64(n)))
	zhZeta.Sub(&zetaN, &one)
	evalBlinded := func(v dvec, b []fr.Element) fr.Element {
		r := p.eval(v, n, zeta)
		be := evalPoly(b, zeta)
		be.Mul(&be, &zhZeta)
		r.Add(&r, &be)
		return r
	}
	lZeta := evalBlinded(can[0], bp.l)
	rZeta := evalBlinded(can[1], bp.r)
	oZeta := evalBlinded(can[2], bp.o)

	tmp := alloc(n)
	p.sCanonical(tmp, 0)
	s1Zeta := p.eval(tmp, n, zeta)
	p.sCanonical(tmp, 1)
	s2Zeta := p.eval(tmp, n, zeta)
	qcpZeta := p.eval(p.qcp, n, zeta)
	p.sCanonical(tmp, 2)

	// Linearized polynomial, written over the blinded Z.
	consts := p.linearizationConstants(lZeta, rZeta, oZeta, s1Zeta, s2Zeta, qcpZeta, alpha, beta, gamma, zeta, zetaN,
		proof.ZShiftedOpening.ClaimedValue)
	linearize(z, z, n+3, tmp, p.ql, p.qr, p.qm, p.qo, p.qk, pi, n, h, np2, &consts)
	h.Free()
	pi.Free()
	linDigest := msm(z.Range(0, n+3, false), p.srs.Range(0, n+3, false))
	linZeta := p.eval(z, n+3, zeta)

	// Batch opening at zeta.
	claimed := []fr.Element{linZeta, lZeta, rZeta, oZeta, s1Zeta, s2Zeta, qcpZeta}
	digests := []kzg.Digest{linDigest, proof.LRO[0], proof.LRO[1], proof.LRO[2], p.vk.S[0], p.vk.S[1], p.vk.Qcp[0]}
	foldGamma, err := deriveGamma(zeta, digests, claimed, proof.ZShiftedOpening.ClaimedValue.Marshal())
	if err != nil {
		return nil, err
	}
	var g fr.Element
	g.Set(&foldGamma)
	for i, c := range can {
		axpy(z, c, g, n)
		p.addBlindingTerms(z, n, g, [][]fr.Element{bp.l, bp.r, bp.o}[i])
		g.Mul(&g, &foldGamma)
		c.Free()
	}
	p.sCanonical(tmp, 0)
	axpy(z, tmp, g, n)
	g.Mul(&g, &foldGamma)
	p.sCanonical(tmp, 1)
	axpy(z, tmp, g, n)
	g.Mul(&g, &foldGamma)
	axpy(z, p.qcp, g, n)
	tmp.Free()
	proof.BatchedProof.ClaimedValues = claimed
	_, proof.BatchedProof.H = p.open(z, n+3, zeta)
	z.Free()

	return proof, nil
}

// quotient returns the coefficients of h on the device; gnark's h1, h2, h3 are its chunks of n+2.
func (p *Prover) quotient(can [3]dvec, z, pi dvec, bp blinding, public []fr.Element, commitmentVal, alpha, beta, gamma fr.Element) dvec {
	n := p.n
	var nInv, one fr.Element
	one.SetOne()
	nInv.SetUint64(uint64(n)).Inverse(&nInv)

	// qk with the public inputs and the bsb22 commitment value, as a sparse update of the circuit's qk.
	delta := make([]fr.Element, len(p.qkPos))
	for i := range public {
		delta[i].Sub(&public[i], &p.qkTrace[i])
	}
	delta[len(public)].Sub(&commitmentVal, &p.qkTrace[len(public)])
	qkDelta := p.sparseCanonical(p.qkPos, delta)
	vadd(p.qk, qkDelta, n)
	qkDelta.Free()
	defer func() {
		qkDelta := p.sparseCanonical(p.qkPos, delta)
		vsub(p.qk, qkDelta, n)
		qkDelta.Free()
	}()

	a, v1, v2, v3, tt, u := alloc(n), alloc(n), alloc(n), alloc(n), alloc(n), alloc(n)
	var quarter, w4, w4Inv, uNInv fr.Element
	quarter.SetUint64(4).Inverse(&quarter)
	w4.Exp(p.cosets[1], big.NewInt(int64(n)))
	var uN fr.Element
	uN.Exp(p.u, big.NewInt(int64(n)))
	w4.Div(&w4, &uN)
	w4Inv.Inverse(&w4)
	uNInv.Inverse(&uN)

	var weights [4][4]fr.Element
	for k := 0; k < 4; k++ {
		c := p.cosets[k]
		tab := p.tabC[k]
		var cn, cn1 fr.Element
		cn.Exp(c, big.NewInt(int64(n)))
		cn1.Sub(&cn, &one)
		eval := func(dst, src dvec) {
			scalePow(dst, src, n, tab)
			ntt(dst, n, icicle_core.KForward)
		}
		scaled := func(b []fr.Element) []fr.Element {
			r := make([]fr.Element, len(b))
			for i := range b {
				r[i].Mul(&b[i], &cn1)
			}
			return r
		}

		eval(v1, can[0])
		blindCoset(v1, n, p.tabW, c, scaled(bp.l))
		eval(v2, can[1])
		blindCoset(v2, n, p.tabW, c, scaled(bp.r))
		eval(v3, can[2])
		blindCoset(v3, n, p.tabW, c, scaled(bp.o))

		eval(tt, p.ql)
		if k > 0 {
			after(nil, p.copyStream, p.copyDone)
		}
		vmul(a, tt, v1, n)
		eval(tt, p.qr)
		vfma(a, tt, v2, n)
		eval(tt, p.qm)
		vfma3(a, tt, v1, v2, n)
		eval(tt, p.qo)
		vfma(a, tt, v3, n)
		eval(tt, p.qk)
		vadd(a, tt, n)
		eval(u, pi)
		eval(tt, p.qcp)
		vfma(a, tt, u, n)

		var kbc fr.Element
		for j, f := range []dvec{v1, v2, v3} {
			p.sCanonical(u, j)
			eval(u, u)
			permS(tt, f, u, n, beta, gamma, j == 0)
			kbc.Mul(&beta, &c)
			if j == 1 {
				kbc.Mul(&kbc, &p.u)
			} else if j == 2 {
				kbc.Mul(&kbc, &p.u2)
			}
			permID(v1, f, n, p.tabW, kbc, gamma, j == 0)
		}

		eval(v2, z)
		blindCoset(v2, n, p.tabW, c, scaled(bp.z))
		var a2l1 fr.Element
		a2l1.Square(&alpha).Mul(&a2l1, &cn1).Mul(&a2l1, &nInv)
		zCombine(a, v1, tt, v2, n, p.tabW, c, alpha, a2l1)

		ntt(a, n, icicle_core.KInverse)
		scalePow(a, a, n, p.tabCInv[k])

		// h_{i+tn} u^{tn} = 1/4 sum_k w4^{-kt} g'_k[i] / Z_H(c_k)
		var zhInv, uPow fr.Element
		zhInv.Inverse(&cn1)
		uPow.SetOne()
		for tIdx := 0; tIdx < 4; tIdx++ {
			var w fr.Element
			w.Exp(w4Inv, big.NewInt(int64(k*tIdx)))
			w.Mul(&w, &quarter).Mul(&w, &zhInv).Mul(&w, &uPow)
			weights[k][tIdx] = w
			uPow.Mul(&uPow, &uNInv)
		}
		if k < 3 {
			after(p.copyStream, nil, p.computeDone)
			d2hAsync(p.hostG[k], a, n*fr.Bytes, p.copyStream)
		}
	}
	for _, b := range []dvec{v1, v2, v3, tt, u} {
		b.Free()
	}

	syncStream(p.copyStream)
	h := alloc(3*n + 8)
	hAccum(h, a, n, weights[3], true)
	for k := 0; k < 3; k++ {
		h2d(a, p.hostG[k], n*fr.Bytes)
		hAccum(h, a, n, weights[k], false)
	}
	a.Free()

	return h
}

func (p *Prover) sCanonical(dst dvec, j int) {
	n := p.n
	sigmaLagrange(dst, p.sigma.Range(j*n, (j+1)*n, false), n, p.tabW, p.u, p.u2)
	ntt(dst, n, icicle_core.KInverse)
}

// sparseCanonical returns the canonical form of the Lagrange vector with vals at pos and zeros elsewhere.
func (p *Prover) sparseCanonical(pos []int, vals []fr.Element) dvec {
	n := p.n
	d := alloc(n)
	memset0(d, n*fr.Bytes)
	pos32 := make([]uint32, len(pos))
	for i := range pos {
		pos32[i] = uint32(pos[i])
	}
	dpos := uploadU32(pos32)
	scatter(d, dpos, vals)
	dpos.Free()
	ntt(d, n, icicle_core.KInverse)
	return d
}

// commitBlinded commits to p + b*(X^n - 1) where p is in canonical form.
func (p *Prover) commitBlinded(v dvec, b []fr.Element) curve.G1Affine {
	n := p.n
	c := msm(v.Range(0, n, false), p.srs.Range(0, n, false))
	var lo, hi curve.G1Affine
	lo.MultiExp(p.srsLo[:len(b)], b, ecc.MultiExpConfig{})
	hi.MultiExp(p.srsHi[:len(b)], b, ecc.MultiExpConfig{})
	hi.Sub(&hi, &lo)
	c.Add(&c, &hi)
	return c
}

// blindCoefficients turns canonical p (n coefficients) into p + b*(X^n - 1) (n + len(b) coefficients).
func (p *Prover) blindCoefficients(v dvec, n int, b []fr.Element) {
	memset0(v.Range(n, n+len(b), false), len(b)*fr.Bytes)
	p.addBlindingTerms(v, n, fr.One(), b)
}

// addBlindingTerms adds s*b*(X^n - 1) to v.
func (p *Prover) addBlindingTerms(v dvec, n int, s fr.Element, b []fr.Element) {
	pos := make([]uint32, 2*len(b))
	for j := range b {
		pos[j], pos[len(b)+j] = uint32(j), uint32(n+j)
	}
	cur := downloadAt(v, pos)
	for j := range b {
		var t fr.Element
		t.Mul(&b[j], &s)
		cur[j].Sub(&cur[j], &t)
		cur[len(b)+j].Add(&cur[len(b)+j], &t)
	}
	dpos := uploadU32(pos)
	scatter(v, dpos, cur)
	dpos.Free()
}

func (p *Prover) eval(v dvec, m int, z fr.Element) fr.Element {
	parts := evalPartials(v, m, z, evalChunk)
	var zc, acc fr.Element
	zc.Exp(z, big.NewInt(evalChunk))
	for i := len(parts) - 1; i >= 0; i-- {
		acc.Mul(&acc, &zc).Add(&acc, &parts[i])
	}
	return acc
}

// open returns f(a) and the commitment to (f - f(a)) / (X - a).
func (p *Prover) open(f dvec, m int, a fr.Element) (fr.Element, curve.G1Affine) {
	parts := evalPartials(f, m, a, evalChunk)
	var ac fr.Element
	ac.Exp(a, big.NewInt(evalChunk))
	carries := make([]fr.Element, len(parts)+1)
	for i := len(parts) - 1; i >= 0; i-- {
		carries[i].Mul(&carries[i+1], &ac).Add(&carries[i], &parts[i])
	}
	q := alloc(m - 1)
	divXMinusA(q, f, m, a, carries, evalChunk)
	c := msm(q, p.srs.Range(0, m-1, false))
	q.Free()
	return carries[0], c
}

func (p *Prover) linearizationConstants(lZeta, rZeta, oZeta, s1Zeta, s2Zeta, qcpZeta, alpha, beta, gamma, zeta, zetaN, zu fr.Element) [10]fr.Element {
	var rl, s1, s2, tmp, uzeta, uuzeta fr.Element
	rl.Mul(&rZeta, &lZeta)
	s1.Mul(&s1Zeta, &beta).Add(&s1, &lZeta).Add(&s1, &gamma)
	tmp.Mul(&s2Zeta, &beta).Add(&tmp, &rZeta).Add(&tmp, &gamma)
	s1.Mul(&s1, &tmp).Mul(&s1, &zu).Mul(&s1, &beta).Mul(&s1, &alpha)

	uzeta.Mul(&zeta, &p.vk.CosetShift)
	uuzeta.Mul(&uzeta, &p.vk.CosetShift)
	s2.Mul(&beta, &zeta).Add(&s2, &lZeta).Add(&s2, &gamma)
	tmp.Mul(&beta, &uzeta).Add(&tmp, &rZeta).Add(&tmp, &gamma)
	s2.Mul(&s2, &tmp)
	tmp.Mul(&beta, &uuzeta).Add(&tmp, &oZeta).Add(&tmp, &gamma)
	s2.Mul(&s2, &tmp)
	s2.Neg(&s2).Mul(&s2, &alpha)

	var zhZeta, zetaNPlusTwo, a2l1, one, den fr.Element
	one.SetOne()
	zetaNPlusTwo.Mul(&zetaN, &zeta).Mul(&zetaNPlusTwo, &zeta)
	zhZeta.Sub(&zetaN, &one)
	den.Sub(&zeta, &one).Inverse(&den)
	a2l1.Mul(&zhZeta, &den).Mul(&a2l1, &alpha).Mul(&a2l1, &alpha).Mul(&a2l1, &p.domain0.CardinalityInv)

	return [10]fr.Element{s1, s2, rl, lZeta, rZeta, oZeta, qcpZeta, a2l1, zhZeta, zetaNPlusTwo}
}

func evalPoly(p []fr.Element, z fr.Element) fr.Element {
	var r fr.Element
	for i := len(p) - 1; i >= 0; i-- {
		r.Mul(&r, &z).Add(&r, &p[i])
	}
	return r
}

func runOnDevice(device *icicle_runtime.Device, f func()) {
	done := make(chan struct{})
	icicle_runtime.RunOnDevice(device, func(...any) {
		defer close(done)
		f()
	})
	<-done
}

func alloc(n int) dvec {
	var d dvec
	if _, e := d.Malloc(fr.Bytes, n); e != icicle_runtime.Success {
		panic(fmt.Sprintf("device malloc of %d elements: %s", n, e.AsString()))
	}
	return d
}

func uploadFr(v []fr.Element) dvec {
	d := alloc(len(v))
	h2d(d, unsafe.Pointer(&v[0]), len(v)*fr.Bytes)
	fromMont(d, len(v))
	return d
}

func uploadU32(v []uint32) dvec {
	var d dvec
	if _, e := d.Malloc(4, len(v)); e != icicle_runtime.Success {
		panic(fmt.Sprintf("device malloc: %s", e.AsString()))
	}
	h2d(d, unsafe.Pointer(&v[0]), len(v)*4)
	return d
}

func downloadAt(v dvec, pos []uint32) []fr.Element {
	out := make([]fr.Element, len(pos))
	for i, p := range pos {
		d2h(unsafe.Pointer(&out[i]), v.Range(int(p), int(p)+1, false), fr.Bytes)
	}
	deviceSync()
	for i := range out {
		var err error
		if out[i], err = fr.LittleEndian.Element((*[fr.Bytes]byte)(unsafe.Pointer(&out[i]))); err != nil {
			panic(err)
		}
	}
	return out
}

func srsBytes(n int) int { return (n + 3) * int(unsafe.Sizeof(curve.G1Affine{})) }

func (p *Prover) uploadSrs() {
	var d dvec
	if _, e := d.Malloc(int(unsafe.Sizeof(curve.G1Affine{})), p.n+3); e != icicle_runtime.Success {
		panic(fmt.Sprintf("device malloc: %s", e.AsString()))
	}
	h2d(d, p.srsHost, srsBytes(p.n))
	p.srs = d
}

func pointsToStd(dst, src []curve.G1Affine) {
	parallel(len(src), func(start, end int) {
		for i := start; i < end; i++ {
			dst[i].X = fp.Element(src[i].X.Bits())
			dst[i].Y = fp.Element(src[i].Y.Bits())
		}
	})
}

func uploadPoints(pts []curve.G1Affine) dvec {
	std := make([]curve.G1Affine, len(pts))
	pointsToStd(std, pts)
	var d dvec
	if _, e := d.Malloc(int(unsafe.Sizeof(std[0])), len(std)); e != icicle_runtime.Success {
		panic(fmt.Sprintf("device malloc: %s", e.AsString()))
	}
	h2d(d, unsafe.Pointer(&std[0]), len(std)*int(unsafe.Sizeof(std[0])))
	deviceSync()
	return d
}

func uploadTab(c fr.Element) dvec {
	tab := make([]fr.Element, tabLo+tabHi)
	tab[0].SetOne()
	for i := 1; i < tabLo; i++ {
		tab[i].Mul(&tab[i-1], &c)
	}
	var step fr.Element
	step.Mul(&tab[tabLo-1], &c)
	tab[tabLo].SetOne()
	for i := 1; i < tabHi; i++ {
		tab[tabLo+i].Mul(&tab[tabLo+i-1], &step)
	}
	d := alloc(len(tab))
	h2d(d, unsafe.Pointer(&tab[0]), len(tab)*fr.Bytes)
	deviceSync()
	return d
}

func ntt(v dvec, n int, dir icicle_core.NTTDir) {
	nttTo(v, v, n, dir)
}

func nttTo(dst, src dvec, n int, dir icicle_core.NTTDir) {
	cfg := icicle_ntt.GetDefaultNttConfig()
	if e := icicle_ntt.Ntt(src.Range(0, n, false), dir, &cfg, dst.Range(0, n, false)); e != icicle_runtime.Success {
		panic(fmt.Sprintf("ntt: %s", e.AsString()))
	}
}

func msmConfig() icicle_core.MSMConfig {
	cfg := icicle_msm.GetDefaultMSMConfig()
	cfg.C = msmWindow
	ext := config_extension.Create()
	ext.SetInt(icicle_core.CUDA_MSM_NOF_CHUNKS, msmChunks)
	cfg.Ext = ext.AsUnsafePointer()
	return cfg
}

func msm(scalars, points dvec) curve.G1Affine {
	cfg := msmConfig()
	res := make(icicle_core.HostSlice[icicle_bn254.Projective], 1)
	if e := icicle_msm.Msm(scalars, points, &cfg, res); e != icicle_runtime.Success {
		panic(fmt.Sprintf("msm: %s", e.AsString()))
	}
	return toAffine(res[0])
}

func msmHost(scalars []fr.Element, points dvec) curve.G1Affine {
	std := make([]fr.Element, len(scalars))
	for i := range scalars {
		std[i] = fr.Element(scalars[i].Bits())
	}
	cfg := msmConfig()
	res := make(icicle_core.HostSlice[icicle_bn254.Projective], 1)
	if e := icicle_msm.Msm(icicle_core.HostSliceFromElements(std), points.Range(0, len(std), false), &cfg, res); e != icicle_runtime.Success {
		panic(fmt.Sprintf("msm: %s", e.AsString()))
	}
	return toAffine(res[0])
}

func toAffine(p icicle_bn254.Projective) curve.G1Affine {
	px, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(p.X.ToBytesLittleEndian()))
	py, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(p.Y.ToBytesLittleEndian()))
	pz, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(p.Z.ToBytesLittleEndian()))
	if pz.IsZero() {
		return curve.G1Affine{}
	}
	var zInv fp.Element
	zInv.Inverse(&pz)
	px.Mul(&px, &zInv)
	py.Mul(&py, &zInv)
	return curve.G1Affine{X: px, Y: py}
}

func parallel(n int, f func(start, end int)) {
	nt := runtime.NumCPU()
	chunk := (n + nt - 1) / nt
	var wg sync.WaitGroup
	for s := 0; s < n; s += chunk {
		wg.Add(1)
		go func(s int) {
			defer wg.Done()
			f(s, min(n, s+chunk))
		}(s)
	}
	wg.Wait()
}

func bindPublicData(fs *fiatshamir.Transcript, challenge string, vk *plonk_bn254.VerifyingKey, publicInputs []fr.Element) error {
	for _, d := range []kzg.Digest{vk.S[0], vk.S[1], vk.S[2], vk.Ql, vk.Qr, vk.Qm, vk.Qo, vk.Qk} {
		if err := fs.Bind(challenge, d.Marshal()); err != nil {
			return err
		}
	}
	for i := range vk.Qcp {
		if err := fs.Bind(challenge, vk.Qcp[i].Marshal()); err != nil {
			return err
		}
	}
	for i := range publicInputs {
		if err := fs.Bind(challenge, publicInputs[i].Marshal()); err != nil {
			return err
		}
	}
	return nil
}

func deriveRandomness(fs *fiatshamir.Transcript, challenge string, points ...*curve.G1Affine) (fr.Element, error) {
	var r fr.Element
	for _, p := range points {
		buf := p.RawBytes()
		if err := fs.Bind(challenge, buf[:]); err != nil {
			return r, err
		}
	}
	b, err := fs.ComputeChallenge(challenge)
	if err != nil {
		return r, err
	}
	r.SetBytes(b)
	return r, nil
}

func deriveGamma(point fr.Element, digests []kzg.Digest, claimedValues []fr.Element, dataTranscript ...[]byte) (fr.Element, error) {
	fs := fiatshamir.NewTranscript(sha256.New(), "gamma")
	if err := fs.Bind("gamma", point.Marshal()); err != nil {
		return fr.Element{}, err
	}
	for i := range digests {
		if err := fs.Bind("gamma", digests[i].Marshal()); err != nil {
			return fr.Element{}, err
		}
	}
	for i := range claimedValues {
		if err := fs.Bind("gamma", claimedValues[i].Marshal()); err != nil {
			return fr.Element{}, err
		}
	}
	for _, d := range dataTranscript {
		if err := fs.Bind("gamma", d); err != nil {
			return fr.Element{}, err
		}
	}
	b, err := fs.ComputeChallenge("gamma")
	if err != nil {
		return fr.Element{}, err
	}
	var gamma fr.Element
	gamma.SetBytes(b)
	return gamma, nil
}
