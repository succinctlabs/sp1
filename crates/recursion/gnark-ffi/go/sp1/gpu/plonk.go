//go:build plonkcuda || groth16cuda

// Package gpu implements gnark's BN254 PLONK and Groth16 provers in CUDA. The proofs are those of
// backend/plonk/bn254 and backend/groth16/bn254, for the same keys, transcripts and verifiers. Nothing
// stays on the GPU between proofs.
package gpu

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"math/bits"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
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
)

const (
	evalChunk = 256
	tabLo     = 1 << 12
	tabHi     = 1 << 14
)

// selector is a Lagrange-form selector stored as indices into its few distinct values.
type selector struct {
	idx   []uint16
	table []fr.Element
}

// PlonkProver holds one circuit's proving key in host memory, the selectors in compact form.
type PlonkProver struct {
	spr     *cs.SparseR1CS
	vk      *plonk_bn254.VerifyingKey
	n       int
	logN    int
	nbPub   int
	domain0 *fft.Domain
	u, u2   fr.Element
	cosets  [4]fr.Element
	commit  constraint.PlonkCommitment

	srs                []curve.G1Affine
	ql, qr, qm, qo, qk selector
	qkPos              []uint32
	sigma              []uint32
	lroWires           []uint32
	qcpPos, piPos      []uint32
	bsbPoints          []curve.G1Affine
	tabW, tabWInv      []fr.Element
	tabC, tabCInv      [4][]fr.Element
	solver             *levelSolver
	hostG              [3][]fr.Element
	copyStream         unsafe.Pointer
	computeDone        unsafe.Pointer
	copyDone           unsafe.Pointer
}

// NewPlonkProver prepares a circuit for proving, keeping what it needs from the proving key.
func NewPlonkProver(spr *cs.SparseR1CS, pk *plonk_bn254.ProvingKey) (*PlonkProver, error) {
	commitments := spr.CommitmentInfo.(constraint.PlonkCommitments)
	if len(commitments) != 1 {
		return nil, fmt.Errorf("gpu: PLONK supports exactly one bsb22 commitment, got %d", len(commitments))
	}
	p := &PlonkProver{spr: spr, vk: pk.Vk, commit: commitments[0]}
	sizeSystem := uint64(spr.GetNbConstraints() + len(spr.Public))
	p.domain0 = fft.NewDomain(sizeSystem)
	domain1 := fft.NewDomain(4*sizeSystem, fft.WithoutPrecompute())
	if domain1.Cardinality != 4*p.domain0.Cardinality {
		return nil, fmt.Errorf("gpu: PLONK expects a quotient domain of 4n")
	}
	if !domain1.FrMultiplicativeGen.Equal(&pk.Vk.CosetShift) || !p.domain0.Generator.Equal(&pk.Vk.Generator) {
		return nil, fmt.Errorf("gpu: proving key domain mismatch")
	}
	n := int(p.domain0.Cardinality)
	p.n, p.logN, p.nbPub = n, bits.TrailingZeros(uint(n)), len(spr.Public)
	p.u = pk.Vk.CosetShift
	p.u2.Square(&p.u)
	p.cosets[0] = p.u
	for k := 1; k < 4; k++ {
		p.cosets[k].Mul(&p.cosets[k-1], &domain1.Generator)
	}
	p.tabW, p.tabWInv = powTable(p.domain0.Generator), powTable(p.domain0.GeneratorInv)
	for k := range p.cosets {
		var inv fr.Element
		inv.Inverse(&p.cosets[k])
		p.tabC[k], p.tabCInv[k] = powTable(p.cosets[k]), powTable(inv)
	}

	trace := plonk_bn254.NewTrace(spr, p.domain0)
	for _, s := range []struct {
		dst *selector
		src []fr.Element
	}{
		{&p.ql, trace.Ql.Coefficients()}, {&p.qr, trace.Qr.Coefficients()}, {&p.qm, trace.Qm.Coefficients()},
		{&p.qo, trace.Qo.Coefficients()}, {&p.qk, trace.Qk.Coefficients()},
	} {
		var err error
		if *s.dst, err = compress(s.src); err != nil {
			return nil, err
		}
	}
	p.sigma = make([]uint32, len(trace.S))
	for i, s := range trace.S {
		p.sigma[i] = uint32(s)
	}
	trace = nil

	for i := 0; i < p.nbPub; i++ {
		p.qkPos = append(p.qkPos, uint32(i))
	}
	p.qkPos = append(p.qkPos, uint32(p.nbPub+p.commit.CommitmentIndex))
	for _, c := range p.commit.Committed {
		p.qcpPos = append(p.qcpPos, uint32(p.nbPub+c))
	}
	p.piPos = append(append([]uint32{}, p.qcpPos...), uint32(p.nbPub+p.commit.CommitmentIndex), uint32(p.nbPub+spr.GetNbConstraints()-1))
	p.bsbPoints = make([]curve.G1Affine, len(p.piPos))
	for i, pos := range p.piPos {
		p.bsbPoints[i] = pk.KzgLagrange.G1[pos]
	}
	p.srs = pk.Kzg.G1[:n+3]
	p.lroWires = lroWires(spr, n)
	p.solver = newSolver(spr)

	for _, v := range [][]uint16{p.ql.idx, p.qr.idx, p.qm.idx, p.qo.idx, p.qk.idx} {
		pin(v)
	}
	pin(p.srs)
	pin(p.sigma)
	pin(p.lroWires)
	p.copyStream, p.computeDone, p.copyDone = newStream(), newEvent(), newEvent()
	return p, nil
}

// compress stores a vector with at most 2^16 distinct values as indices into a table of them.
func compress(v []fr.Element) (selector, error) {
	s := selector{idx: make([]uint16, len(v))}
	pos := map[fr.Element]uint16{}
	for i := range v {
		j, ok := pos[v[i]]
		if !ok {
			if len(s.table) == 1<<16 {
				return selector{}, fmt.Errorf("gpu: selector has more than 2^16 distinct values")
			}
			j = uint16(len(s.table))
			pos[v[i]] = j
			s.table = append(s.table, v[i])
		}
		s.idx[i] = j
	}
	return s, nil
}

// powTable returns c^i for i < 2^12 followed by c^(2^12 * i) for i < 2^14.
func powTable(c fr.Element) []fr.Element {
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
	return tab
}

// Prove computes a PLONK proof for the given full witness: the public inputs, then the secret ones.
func (p *PlonkProver) Prove(fullWitness fr.Vector) (proof *plonk_bn254.Proof, err error) {
	defer freeAll()
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("gpu: %v", r)
		}
	}()
	return p.prove(p.newDevice(), fullWitness)
}

// device holds the per-proof device buffers.
type device struct {
	tabW, tabWInv dvec
	tabC, tabCInv [4]dvec
	srs           dvec
	sel           [5]dvec
	sigma         dvec
	qcpPos, piPos dvec
	// values and wires hold the solution, from which l, r and o are gathered when needed.
	values, wires dvec
}

func (p *PlonkProver) newDevice() *device {
	d := &device{tabW: upload(p.tabW), tabWInv: upload(p.tabWInv)}
	for k := range p.tabC {
		d.tabC[k], d.tabCInv[k] = upload(p.tabC[k]), upload(p.tabCInv[k])
	}
	for i, s := range []selector{p.ql, p.qr, p.qm, p.qo, p.qk} {
		d.sel[i] = upload(s.idx)
	}
	d.sigma = upload(p.sigma)
	d.qcpPos, d.piPos = upload(p.qcpPos), upload(p.piPos)
	return d
}

func (p *PlonkProver) uploadSrs(d *device) { d.srs = upload(p.srs) }

func (p *PlonkProver) dropSrs(d *device) {
	d.srs.free()
	d.srs = dvec{}
}

// canonical turns a Lagrange-form vector into its coefficients in place.
func (p *PlonkProver) canonical(d *device, v dvec) {
	ntt(v, p.logN, d.tabWInv, &p.domain0.CardinalityInv)
}

// cosetEval writes the evaluations of the canonical polynomial src on coset k into dst.
func (p *PlonkProver) cosetEval(d *device, dst, src dvec, k int) {
	scalePow(dst, src, p.n, d.tabC[k])
	ntt(dst, p.logN, d.tabW, nil)
}

// selectorCanonical writes the coefficients of selector i into dst; overrides replace Lagrange values.
func (p *PlonkProver) selectorCanonical(d *device, dst dvec, i int, overrides []fr.Element) {
	s := []selector{p.ql, p.qr, p.qm, p.qo, p.qk}[i]
	expand(dst, d.sel[i], s.table, p.n)
	if overrides != nil {
		pos := upload(p.qkPos)
		scatter(dst, pos, overrides)
		pos.free()
	}
	p.canonical(d, dst)
}

// lroCanonical writes the coefficients of l, r or o into dst.
func (p *PlonkProver) lroCanonical(d *device, dst dvec, j int) {
	gather(dst, d.values, d.wires.at(j*p.n, 4), p.n)
	p.canonical(d, dst)
}

func (p *PlonkProver) sCanonical(d *device, dst dvec, j int) {
	sigmaLagrange(dst, d.sigma.at(j*p.n, 4), p.n, d.tabW, p.u, p.u2)
	p.canonical(d, dst)
}

// sparseCanonical writes the coefficients of the Lagrange vector with vals at pos into dst.
func (p *PlonkProver) sparseCanonical(d *device, dst, pos dvec, vals []fr.Element) {
	memset0(dst, p.n*fr.Bytes)
	scatter(dst, pos, vals)
	p.canonical(d, dst)
}

func (p *PlonkProver) qcpCanonical(d *device, dst dvec) {
	ones := make([]fr.Element, len(p.qcpPos))
	for i := range ones {
		ones[i].SetOne()
	}
	p.sparseCanonical(d, dst, d.qcpPos, ones)
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

func (p *PlonkProver) prove(d *device, wWitness fr.Vector) (*plonk_bn254.Proof, error) {
	n := p.n
	proof := &plonk_bn254.Proof{Bsb22Commitments: make([]kzg.Digest, 1)}
	bp := blinding{l: randomPoly(1), r: randomPoly(1), o: randomPoly(1), z: randomPoly(2)}
	public := wWitness[:p.nbPub]

	// Solve, computing the bsb22 commitment on the GPU.
	var piVals []fr.Element
	var commitmentVal fr.Element
	htf := hash_to_field.New([]byte("BSB22-Plonk"))
	hint := solver.OverrideHint(solver.GetHintID(fcs.Bsb22CommitmentComputePlaceholder), func(_ *big.Int, ins, outs []*big.Int) (err error) {
		// The hint runs on a solver goroutine, out of reach of Prove's recover.
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("bsb22 commitment: %v", r)
			}
		}()
		ins = ins[1:]
		piVals = make([]fr.Element, len(p.piPos))
		for i := range ins {
			piVals[i].SetBigInt(ins[i])
		}
		piVals[len(ins)].SetRandom()
		piVals[len(ins)+1].SetRandom()
		c := p.commitPi(piVals)
		proof.Bsb22Commitments[0] = c
		htf.Write(c.Marshal())
		hashBts := htf.Sum(nil)
		htf.Reset()
		nbBuf := min(fr.Bytes, htf.Size())
		commitmentVal.SetBytes(hashBts[:nbBuf])
		commitmentVal.BigInt(outs[0])
		return nil
	})
	if err := p.solver.solve(wWitness, hint); err != nil {
		return nil, err
	}

	// The commitments to l, r and o.
	d.values, d.wires = upload(p.solver.values), upload(p.lroWires)
	p.uploadSrs(d)
	tmp := alloc(n)
	for i, b := range [][]fr.Element{bp.l, bp.r, bp.o} {
		p.lroCanonical(d, tmp, i)
		proof.LRO[i] = p.commitBlinded(d, tmp, b)
	}
	tmp.free()

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
	ratio(z, d.values, d.wires, d.sigma, n, d.tabW, beta, gamma, p.u, p.u2)
	scanMul(z, n)
	p.canonical(d, z)
	proof.Z = p.commitBlinded(d, z, bp.z)

	alpha, err := deriveRandomness(fs, "alpha", &proof.Bsb22Commitments[0], &proof.Z)
	if err != nil {
		return nil, err
	}

	// The quotient needs the memory the SRS takes.
	p.dropSrs(d)
	qk := make([]fr.Element, len(p.qkPos))
	copy(qk, public)
	qk[len(public)] = commitmentVal
	h := p.quotient(d, z, piVals, qk, bp, alpha, beta, gamma)
	p.uploadSrs(d)

	np2 := n + 2
	for i := 0; i < 3; i++ {
		proof.H[i] = msm(h.fr(i*np2), d.srs, np2)
	}
	p.dropSrs(d)

	zeta, err := deriveRandomness(fs, "zeta", &proof.H[0], &proof.H[1], &proof.H[2])
	if err != nil {
		return nil, err
	}

	// Open Z (blinded) at zeta * omega.
	var zetaShifted fr.Element
	zetaShifted.Mul(&zeta, &p.vk.Generator)
	p.blindCoefficients(z, n, bp.z)
	var qz dvec
	proof.ZShiftedOpening.ClaimedValue, qz = p.divide(z, n+3, zetaShifted)

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
	tmp = alloc(n)
	var lro [3]fr.Element
	for i, b := range [][]fr.Element{bp.l, bp.r, bp.o} {
		p.lroCanonical(d, tmp, i)
		lro[i] = evalBlinded(tmp, b)
	}
	lZeta, rZeta, oZeta := lro[0], lro[1], lro[2]
	p.sCanonical(d, tmp, 0)
	s1Zeta := p.eval(tmp, n, zeta)
	p.sCanonical(d, tmp, 1)
	s2Zeta := p.eval(tmp, n, zeta)
	p.qcpCanonical(d, tmp)
	qcpZeta := p.eval(tmp, n, zeta)

	// The linearized polynomial, written over the blinded Z one term at a time.
	c := p.linearizationConstants(lZeta, rZeta, oZeta, s1Zeta, s2Zeta, alpha, beta, gamma, zeta, zetaN,
		proof.ZShiftedOpening.ClaimedValue)
	var zScale fr.Element
	zScale.Add(&c.s2, &c.a2l1)
	vscale(z, zScale, n+3)
	p.sCanonical(d, tmp, 2)
	axpy(z, tmp, c.s1, n)
	// ql, qr, qm, qo and the circuit's qk, without the public inputs.
	for i, coeff := range []fr.Element{lZeta, rZeta, c.rl, oZeta, one} {
		p.selectorCanonical(d, tmp, i, nil)
		axpy(z, tmp, coeff, n)
	}
	p.sparseCanonical(d, tmp, d.piPos, piVals)
	axpy(z, tmp, qcpZeta, n)
	// - Z_H(zeta) * (h1 + zeta^(n+2) h2 + zeta^(2(n+2)) h3)
	var hc fr.Element
	hc.Neg(&zhZeta)
	for i := 0; i < 3; i++ {
		axpy(z, h.fr(i*np2), hc, np2)
		hc.Mul(&hc, &c.zn2)
	}
	h.free()
	tmp.free()
	p.uploadSrs(d)
	proof.ZShiftedOpening.H = msm(qz, d.srs, n+2)
	qz.free()
	linDigest := msm(z, d.srs, n+3)
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
	tmp = alloc(n)
	for i, b := range [][]fr.Element{bp.l, bp.r, bp.o} {
		p.lroCanonical(d, tmp, i)
		axpy(z, tmp, g, n)
		p.addBlindingTerms(z, n, g, b)
		g.Mul(&g, &foldGamma)
	}
	p.sCanonical(d, tmp, 0)
	axpy(z, tmp, g, n)
	g.Mul(&g, &foldGamma)
	p.sCanonical(d, tmp, 1)
	axpy(z, tmp, g, n)
	g.Mul(&g, &foldGamma)
	p.qcpCanonical(d, tmp)
	axpy(z, tmp, g, n)
	tmp.free()
	proof.BatchedProof.ClaimedValues = claimed
	_, q := p.divide(z, n+3, zeta)
	proof.BatchedProof.H = msm(q, d.srs, n+2)
	return proof, nil
}

// commitPi commits to the bsb22 committed values in Lagrange form.
func (p *PlonkProver) commitPi(vals []fr.Element) curve.G1Affine {
	points, scalars := upload(p.bsbPoints), upload(vals)
	defer points.free()
	defer scalars.free()
	return msm(scalars, points, len(vals))
}

// quotient returns the coefficients of h on the device; gnark's h1, h2, h3 are its chunks of n+2.
func (p *PlonkProver) quotient(d *device, z dvec, piVals, qk []fr.Element, bp blinding, alpha, beta, gamma fr.Element) dvec {
	n := p.n
	var nInv, one fr.Element
	one.SetOne()
	nInv.SetUint64(uint64(n)).Inverse(&nInv)

	a, x, y, t, sv := alloc(n), alloc(n), alloc(n), alloc(n), alloc(n)
	var quarter, w4, w4Inv, uN, uNInv fr.Element
	quarter.SetUint64(4).Inverse(&quarter)
	w4.Exp(p.cosets[1], big.NewInt(int64(n)))
	uN.Exp(p.u, big.NewInt(int64(n)))
	w4.Div(&w4, &uN)
	w4Inv.Inverse(&w4)
	uNInv.Inverse(&uN)
	if p.hostG[0] == nil {
		for k := range p.hostG {
			p.hostG[k] = make([]fr.Element, n)
			pin(p.hostG[k])
		}
	}

	var weights [4][4]fr.Element
	for k := 0; k < 4; k++ {
		c := p.cosets[k]
		var cn, cn1 fr.Element
		cn.Exp(c, big.NewInt(int64(n)))
		cn1.Sub(&cn, &one)
		eval := func(dst, src dvec) { p.cosetEval(d, dst, src, k) }
		blind := func(dst dvec, b []fr.Element) {
			r := make([]fr.Element, len(b))
			for i := range b {
				r[i].Mul(&b[i], &cn1)
			}
			blindCoset(dst, n, d.tabW, c, r)
		}
		lro := func(dst dvec, j int, b []fr.Element) {
			p.lroCanonical(d, dst, j)
			eval(dst, dst)
			blind(dst, b)
		}
		sel := func(dst dvec, i int, overrides []fr.Element) {
			p.selectorCanonical(d, dst, i, overrides)
			eval(dst, dst)
		}
		sigma := func(dst dvec, j int) {
			p.sCanonical(d, dst, j)
			eval(dst, dst)
		}

		// Gate constraint, with x, y, t holding l, r, o.
		lro(x, 0, bp.l)
		lro(y, 1, bp.r)
		lro(t, 2, bp.o)
		sel(sv, 0, nil)
		if k > 0 {
			after(nil, p.copyStream, p.copyDone)
		}
		vmul(a, sv, x, n)
		sel(sv, 1, nil)
		vfma(a, sv, y, n)
		sel(sv, 2, nil)
		vfma3(a, sv, x, y, n)
		sel(sv, 3, nil)
		vfma(a, sv, t, n)
		sel(sv, 4, qk)
		vadd(a, sv, n)

		// Copy constraint: x = prod_j (f_j + beta*k_j*x + gamma), y = prod_j (f_j + beta*s_j + gamma).
		var kbc fr.Element
		kbc.Mul(&beta, &c)
		permID(x, x, n, d.tabW, kbc, gamma, true)
		kbc.Mul(&kbc, &p.u)
		permID(x, y, n, d.tabW, kbc, gamma, false)
		kbc.Mul(&kbc, &p.u)
		permID(x, t, n, d.tabW, kbc, gamma, false)
		sigma(sv, 1)
		permS(y, y, sv, n, beta, gamma, true)
		sigma(sv, 2)
		permS(y, t, sv, n, beta, gamma, false)
		lro(t, 0, bp.l)
		sigma(sv, 0)
		permS(y, t, sv, n, beta, gamma, false)

		eval(sv, z)
		blind(sv, bp.z)
		var a2l1 fr.Element
		a2l1.Square(&alpha).Mul(&a2l1, &cn1).Mul(&a2l1, &nInv)
		zCombine(a, x, y, sv, n, d.tabW, c, alpha, a2l1)

		// The bsb22 commitment's gate term.
		p.sparseCanonical(d, x, d.piPos, piVals)
		eval(x, x)
		p.qcpCanonical(d, y)
		eval(y, y)
		vfma(a, x, y, n)

		p.canonical(d, a)
		scalePow(a, a, n, d.tabCInv[k])

		// h_{i+tn} u^{tn} = 1/4 sum_k w4^{-kt} g'_k[i] / Z_H(c_k)
		var zhInv, uPow fr.Element
		zhInv.Inverse(&cn1)
		uPow.SetOne()
		for t := 0; t < 4; t++ {
			var w fr.Element
			w.Exp(w4Inv, big.NewInt(int64(k*t)))
			w.Mul(&w, &quarter).Mul(&w, &zhInv).Mul(&w, &uPow)
			weights[k][t] = w
			uPow.Mul(&uPow, &uNInv)
		}
		if k < 3 {
			after(p.copyStream, nil, p.computeDone)
			d2hAsync(unsafe.Pointer(&p.hostG[k][0]), a, n*fr.Bytes, p.copyStream)
		}
	}
	for _, b := range []dvec{x, y, t, sv} {
		b.free()
	}

	syncStream(p.copyStream)
	h := alloc(3*n + 8)
	hAccum(h, a, n, weights[3], true)
	for k := 0; k < 3; k++ {
		h2d(a, unsafe.Pointer(&p.hostG[k][0]), n*fr.Bytes)
		hAccum(h, a, n, weights[k], false)
	}
	a.free()
	return h
}

// commitBlinded commits to p + b*(X^n - 1) where p is in canonical form.
func (p *PlonkProver) commitBlinded(d *device, v dvec, b []fr.Element) curve.G1Affine {
	n := p.n
	c := msm(v, d.srs, n)
	var lo, hi curve.G1Affine
	lo.MultiExp(p.srs[:len(b)], b, ecc.MultiExpConfig{})
	hi.MultiExp(p.srs[n:n+len(b)], b, ecc.MultiExpConfig{})
	hi.Sub(&hi, &lo)
	c.Add(&c, &hi)
	return c
}

// blindCoefficients turns canonical p (n coefficients) into p + b*(X^n - 1) (n + len(b) coefficients).
func (p *PlonkProver) blindCoefficients(v dvec, n int, b []fr.Element) {
	memset0(v.fr(n), len(b)*fr.Bytes)
	p.addBlindingTerms(v, n, fr.One(), b)
}

// addBlindingTerms adds s*b*(X^n - 1) to v.
func (p *PlonkProver) addBlindingTerms(v dvec, n int, s fr.Element, b []fr.Element) {
	pos := make([]uint32, 2*len(b))
	for j := range b {
		pos[j], pos[len(b)+j] = uint32(j), uint32(n+j)
	}
	cur := make([]fr.Element, len(pos))
	for i, at := range pos {
		d2h(unsafe.Pointer(&cur[i]), v.fr(int(at)), fr.Bytes)
	}
	deviceSync()
	for j := range b {
		var t fr.Element
		t.Mul(&b[j], &s)
		cur[j].Sub(&cur[j], &t)
		cur[len(b)+j].Add(&cur[len(b)+j], &t)
	}
	dpos := upload(pos)
	scatter(v, dpos, cur)
	dpos.free()
}

func (p *PlonkProver) eval(v dvec, m int, z fr.Element) fr.Element {
	parts := evalPartials(v, m, z, evalChunk)
	var zc, acc fr.Element
	zc.Exp(z, big.NewInt(evalChunk))
	for i := len(parts) - 1; i >= 0; i-- {
		acc.Mul(&acc, &zc).Add(&acc, &parts[i])
	}
	return acc
}

// divide returns f(a) and the coefficients of (f - f(a)) / (X - a) on the device.
func (p *PlonkProver) divide(f dvec, m int, a fr.Element) (fr.Element, dvec) {
	parts := evalPartials(f, m, a, evalChunk)
	var ac fr.Element
	ac.Exp(a, big.NewInt(evalChunk))
	carries := make([]fr.Element, len(parts)+1)
	for i := len(parts) - 1; i >= 0; i-- {
		carries[i].Mul(&carries[i+1], &ac).Add(&carries[i], &parts[i])
	}
	q := alloc(m - 1)
	divXMinusA(q, f, m, a, carries, evalChunk)
	return carries[0], q
}

type linConsts struct {
	s1, s2, rl, a2l1, zn2 fr.Element
}

func (p *PlonkProver) linearizationConstants(lZeta, rZeta, oZeta, s1Zeta, s2Zeta, alpha, beta, gamma, zeta, zetaN, zu fr.Element) linConsts {
	var c linConsts
	var tmp, uzeta, uuzeta fr.Element
	c.rl.Mul(&rZeta, &lZeta)
	c.s1.Mul(&s1Zeta, &beta).Add(&c.s1, &lZeta).Add(&c.s1, &gamma)
	tmp.Mul(&s2Zeta, &beta).Add(&tmp, &rZeta).Add(&tmp, &gamma)
	c.s1.Mul(&c.s1, &tmp).Mul(&c.s1, &zu).Mul(&c.s1, &beta).Mul(&c.s1, &alpha)

	uzeta.Mul(&zeta, &p.vk.CosetShift)
	uuzeta.Mul(&uzeta, &p.vk.CosetShift)
	c.s2.Mul(&beta, &zeta).Add(&c.s2, &lZeta).Add(&c.s2, &gamma)
	tmp.Mul(&beta, &uzeta).Add(&tmp, &rZeta).Add(&tmp, &gamma)
	c.s2.Mul(&c.s2, &tmp)
	tmp.Mul(&beta, &uuzeta).Add(&tmp, &oZeta).Add(&tmp, &gamma)
	c.s2.Mul(&c.s2, &tmp)
	c.s2.Neg(&c.s2).Mul(&c.s2, &alpha)

	var zhZeta, one, den fr.Element
	one.SetOne()
	c.zn2.Mul(&zetaN, &zeta).Mul(&c.zn2, &zeta)
	zhZeta.Sub(&zetaN, &one)
	den.Sub(&zeta, &one).Inverse(&den)
	c.a2l1.Mul(&zhZeta, &den).Mul(&c.a2l1, &alpha).Mul(&c.a2l1, &alpha).Mul(&c.a2l1, &p.domain0.CardinalityInv)
	return c
}

func evalPoly(p []fr.Element, z fr.Element) fr.Element {
	var r fr.Element
	for i := len(p) - 1; i >= 0; i-- {
		r.Mul(&r, &z).Add(&r, &p[i])
	}
	return r
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
