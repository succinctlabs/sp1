//go:build cuda

// Package gpu implements gnark's BN254 PLONK and Groth16 provers in CUDA. The proofs are those of
// backend/plonk/bn254 and backend/groth16/bn254, for the same keys, transcripts and verifiers. Nothing
// stays on the GPU between proofs.
package gpu

import (
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"math/bits"
	"slices"
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
	cids  []uint32
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
	bsbCompressed      []byte
	decodedSRS         int
	tabW, tabWInv      []fr.Element
	tabC, tabCInv      [4][]fr.Element
	solver             *levelSolver
	hostG              [3][]fr.Element
	copyStream         unsafe.Pointer
	computeDone        unsafe.Pointer
	copyDone           unsafe.Pointer
	uploaded           unsafe.Pointer
}

// PlonkTrace contains the CPU-only circuit data shared by all witnesses.
type plonkTrace struct {
	wires, sigma []uint32
	sel          [5]selector
	solver       *levelSolver
}

// PreparePlonkTrace builds the trace while the STARK prover is using the GPU.
func preparePlonkTrace(spr *cs.SparseR1CS) (*plonkTrace, error) {
	n := int(ecc.NextPowerOfTwo(uint64(spr.GetNbConstraints() + len(spr.Public))))
	wires, sel, err := newTrace(spr, n)
	if err != nil {
		return nil, err
	}
	sigma := permutation(wires, len(spr.Public)+len(spr.Secret)+spr.NbInternalVariables)
	solver, err := newSolver(spr, wires, sel)
	if err != nil {
		return nil, err
	}
	return &plonkTrace{wires: wires, sel: sel, sigma: sigma, solver: solver}, nil
}

// NewPlonkProver prepares the host circuit and reads the proving key. The first proof
// decompresses its points once it has the GPU.
func NewPlonkProver(spr *cs.SparseR1CS, r io.Reader) (*PlonkProver, error) {
	vk := &plonk_bn254.VerifyingKey{}
	if _, err := vk.ReadFrom(r); err != nil {
		return nil, err
	}
	commitments := spr.CommitmentInfo.(constraint.PlonkCommitments)
	if len(commitments) != 1 {
		return nil, fmt.Errorf("gpu: PLONK supports exactly one bsb22 commitment, got %d", len(commitments))
	}
	// Debug info only describes failed constraints in errors.
	spr.DebugInfo, spr.MDebug = nil, nil
	p := &PlonkProver{spr: spr, vk: vk, commit: commitments[0]}
	sizeSystem := uint64(spr.GetNbConstraints() + len(spr.Public))
	p.domain0 = fft.NewDomain(sizeSystem, fft.WithoutPrecompute())
	domain1 := fft.NewDomain(4*sizeSystem, fft.WithoutPrecompute())
	if domain1.Cardinality != 4*p.domain0.Cardinality {
		return nil, fmt.Errorf("gpu: PLONK expects a quotient domain of 4n")
	}
	if !domain1.FrMultiplicativeGen.Equal(&vk.CosetShift) || !p.domain0.Generator.Equal(&vk.Generator) {
		return nil, fmt.Errorf("gpu: proving key domain mismatch")
	}
	n := int(p.domain0.Cardinality)
	p.n, p.logN, p.nbPub = n, bits.TrailingZeros(uint(n)), len(spr.Public)
	p.u = vk.CosetShift
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

	for i := 0; i < p.nbPub; i++ {
		p.qkPos = append(p.qkPos, uint32(i))
	}
	p.qkPos = append(p.qkPos, uint32(p.nbPub+p.commit.CommitmentIndex))
	for _, c := range p.commit.Committed {
		p.qcpPos = append(p.qcpPos, uint32(p.nbPub+c))
	}
	p.piPos = append(append([]uint32{}, p.qcpPos...), uint32(p.nbPub+p.commit.CommitmentIndex))
	if last := spr.GetNbConstraints() - 1; last != p.commit.CommitmentIndex {
		p.piPos = append(p.piPos, uint32(p.nbPub+last))
	}

	// The key's points are read while the trace is built.
	keyRead := make(chan error, 1)
	go func() {
		keyRead <- func() error {
			var nb uint32
			var err error
			if err = binary.Read(r, binary.BigEndian, &nb); err != nil {
				return err
			}
			if int(nb) < n+3 {
				return fmt.Errorf("gpu: proving key has %d SRS points, expected at least %d", nb, n+3)
			}
			p.srs = make([]curve.G1Affine, n+3)
			pin(p.srs)
			if _, err = io.ReadFull(r, p.compressedSRS()); err != nil {
				return err
			}
			if _, err = io.CopyN(io.Discard, r, int64(int(nb)-n-3)*curve.SizeOfG1AffineCompressed); err != nil {
				return err
			}
			if err = binary.Read(r, binary.BigEndian, &nb); err != nil {
				return err
			}
			// Decompressing all Lagrange points would take seconds, and only those at piPos are used.
			order := make([]int, len(p.piPos))
			for i := range order {
				order[i] = i
			}
			slices.SortFunc(order, func(a, b int) int { return cmp.Compare(p.piPos[a], p.piPos[b]) })
			comp := make([]byte, len(p.piPos)*curve.SizeOfG1AffineCompressed)
			var buf [curve.SizeOfG1AffineCompressed]byte
			next := 0
			for _, i := range order {
				pos := int(p.piPos[i])
				if pos >= int(nb) {
					return fmt.Errorf("gpu: proving key has %d Lagrange points, expected more than %d", nb, pos)
				}
				if pos >= next {
					if _, err = io.CopyN(io.Discard, r, int64(pos-next)*curve.SizeOfG1AffineCompressed); err != nil {
						return err
					}
					if _, err = io.ReadFull(r, buf[:]); err != nil {
						return err
					}
					next = pos + 1
				}
				copy(comp[i*curve.SizeOfG1AffineCompressed:], buf[:])
			}
			p.bsbPoints = make([]curve.G1Affine, len(p.piPos))
			p.bsbCompressed = comp
			return nil
		}()
	}()

	trace, err := preparePlonkTrace(spr)
	keyErr := <-keyRead
	if err != nil {
		return nil, err
	}
	if keyErr != nil {
		return nil, keyErr
	}
	p.lroWires, p.sigma, p.solver = trace.wires, trace.sigma, trace.solver
	p.ql, p.qr, p.qm, p.qo, p.qk = trace.sel[0], trace.sel[1], trace.sel[2], trace.sel[3], trace.sel[4]

	for _, v := range [][]uint16{p.ql.idx, p.qr.idx, p.qm.idx, p.qo.idx, p.qk.idx} {
		pin(v)
	}
	pin(p.sigma)
	pin(p.lroWires)
	p.copyStream, p.computeDone, p.copyDone, p.uploaded = newStream(), newEvent(), newEvent(), newEvent()
	return p, nil
}

// Store compressed points in the upper half of their eventual destination. Decoding
// forward consumes each input chunk before its output can reach any unread bytes.
func (p *PlonkProver) compressedSRS() []byte {
	size := len(p.srs) * curve.SizeOfG1AffineUncompressed
	return unsafe.Slice((*byte)(unsafe.Pointer(&p.srs[0])), size)[size/2:]
}

func (p *PlonkProver) decodeKey() error {
	const chunk = 1 << 21
	for p.decodedSRS < len(p.srs) {
		i := p.decodedSRS
		end := min(i+chunk, len(p.srs))
		encoded := p.compressedSRS()[i*curve.SizeOfG1AffineCompressed : end*curve.SizeOfG1AffineCompressed]
		if err := decompressG1(p.srs[i:end], encoded); err != nil {
			return err
		}
		p.decodedSRS = end
	}
	if p.bsbCompressed != nil {
		if err := decompressG1(p.bsbPoints, p.bsbCompressed); err != nil {
			return err
		}
		p.bsbCompressed = nil
	}
	return nil
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
	defer func() { p.solver.values = nil }()
	defer freeAll()
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("gpu: %v", r)
		}
	}()
	if err := p.decodeKey(); err != nil {
		return nil, err
	}
	return p.prove(p.newDevice(), fullWitness)
}

// device holds the per-proof device buffers.
type device struct {
	tabW, tabWInv dvec
	tabC, tabCInv [4]dvec
	srs           dvec
	sel, selTab   [5]dvec
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
		d.selTab[i] = upload(s.table)
	}
	d.qcpPos, d.piPos = upload(p.qcpPos), upload(p.piPos)
	return d
}

// uploadState copies the solution, the permutation and the selectors to the device.
func (p *PlonkProver) uploadState(d *device) {
	d.values, d.wires, d.sigma = upload(p.solver.values), upload(p.lroWires), upload(p.sigma)
	for i, s := range []selector{p.ql, p.qr, p.qm, p.qo, p.qk} {
		d.sel[i] = upload(s.idx)
	}
}

func (d *device) dropState() {
	for _, v := range append([]dvec{d.values, d.wires, d.sigma}, d.sel[:]...) {
		v.free()
	}
}

// uploadSrs starts copying the SRS to the device.
func (p *PlonkProver) uploadSrs(d *device) {
	size := len(p.srs) * int(unsafe.Sizeof(p.srs[0]))
	d.srs = allocBytes(size, len(p.srs))
	h2dAsync(d.srs, unsafe.Pointer(&p.srs[0]), size, p.copyStream)
}

// waitUploads makes the work queued after it wait for the uploads started so far.
func (p *PlonkProver) waitUploads() { after(nil, p.copyStream, p.uploaded) }

// hostBuffer allocates a pinned coset only when the device cannot hold it.
func (p *PlonkProver) hostBuffer(i int) []fr.Element {
	if p.hostG[i] == nil {
		p.hostG[i] = make([]fr.Element, p.n)
		pin(p.hostG[i])
	}
	return p.hostG[i]
}

func (p *PlonkProver) dropSrs(d *device) {
	d.srs.free()
	d.srs = dvec{}
}

// zCanonical computes the copy constraint accumulator, which is cheaper to recompute than to keep.
func (p *PlonkProver) zCanonical(d *device, z dvec, beta, gamma fr.Element) {
	ratio(z, d.values, d.wires, d.sigma, p.n, d.tabW, beta, gamma, p.u, p.u2)
	scanMul(z, p.n)
	p.canonical(d, z)
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

// The *Canonical functions write coefficients into dst in bit-reversed order.

// lagrangeCanonical reads a Lagrange-form vector from src, or dst when src is nil.
func (p *PlonkProver) lagrangeCanonical(d *device, dst dvec, src *nttSrc) {
	nttDIF(dst, p.logN, d.tabWInv, &p.domain0.CardinalityInv, src)
}

// selectorCanonical handles selector i; overrides replace its Lagrange values at qkPos.
func (p *PlonkProver) selectorCanonical(d *device, dst dvec, i int, overrides []fr.Element) {
	if overrides == nil {
		p.lagrangeCanonical(d, dst, srcExpand(d.selTab[i], d.sel[i]))
		return
	}
	s := []selector{p.ql, p.qr, p.qm, p.qo, p.qk}[i]
	expand(dst, d.sel[i], s.table, p.n)
	pos := upload(p.qkPos)
	scatter(dst, pos, overrides)
	pos.free()
	p.lagrangeCanonical(d, dst, nil)
}

// lroCanonical handles l, r or o.
func (p *PlonkProver) lroCanonical(d *device, dst dvec, j int) {
	p.lagrangeCanonical(d, dst, srcGather(d.values, d.wires.at(j*p.n, 4)))
}

func (p *PlonkProver) sCanonical(d *device, dst dvec, j int) {
	p.lagrangeCanonical(d, dst, srcSigma(d.sigma.at(j*p.n, 4), d.tabW, p.u, p.u2))
}

// sparseCanonical handles the Lagrange vector with vals at pos.
func (p *PlonkProver) sparseCanonical(d *device, dst, pos dvec, vals []fr.Element) {
	memset0(dst, p.n*fr.Bytes)
	scatter(dst, pos, vals)
	p.lagrangeCanonical(d, dst, nil)
}

func (p *PlonkProver) qcpLagrange(d *device, dst dvec) {
	ones := make([]fr.Element, len(p.qcpPos))
	for i := range ones {
		ones[i].SetOne()
	}
	memset0(dst, p.n*fr.Bytes)
	scatter(dst, d.qcpPos, ones)
}

func (p *PlonkProver) qcpCanonical(d *device, dst dvec) {
	p.qcpLagrange(d, dst)
	p.lagrangeCanonical(d, dst, nil)
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
		piVals[len(piVals)-1].SetRandom()
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
	p.uploadSrs(d)
	if err := p.solver.solve(wWitness, hint); err != nil {
		return nil, err
	}

	// The commitments to l, r and o.
	p.uploadState(d)
	p.waitUploads()
	tmp := alloc(n)
	for i, b := range [][]fr.Element{bp.l, bp.r, bp.o} {
		p.lroCanonical(d, tmp, i)
		bitrev(tmp, p.logN)
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
	p.zCanonical(d, z, beta, gamma)
	proof.Z = p.commitBlinded(d, z, bp.z)

	alpha, err := deriveRandomness(fs, "alpha", &proof.Bsb22Commitments[0], &proof.Z)
	if err != nil {
		return nil, err
	}

	// Five coset buffers and the three quotient chunks can stay on larger devices.
	// Leave room for the sparse selector overrides and temporary CUDA allocations.
	p.dropSrs(d)
	if freeMemory() < uint64(5*n)*fr.Bytes+(256<<20) {
		// The third spill buffer is idle until that coset has been evaluated.
		d2h(unsafe.Pointer(&p.hostBuffer(2)[0]), z, n*fr.Bytes)
		z.free()
		z = dvec{}
	}
	qk := make([]fr.Element, len(p.qkPos))
	copy(qk, public)
	qk[len(public)] = commitmentVal
	h := p.quotient(d, z, piVals, qk, bp, alpha, beta, gamma)

	if z.p == nil {
		z = alloc(n + 3)
		p.zCanonical(d, z, beta, gamma)
	}
	d.dropState()
	p.uploadSrs(d)
	p.waitUploads()
	np2 := n + 2
	for i := 0; i < 3; i++ {
		proof.H[i] = msm(h.fr(i*np2), d.srs, np2)
	}

	zeta, err := deriveRandomness(fs, "zeta", &proof.H[0], &proof.H[1], &proof.H[2])
	if err != nil {
		return nil, err
	}
	var zetaN, zhZeta, zn2, one fr.Element
	one.SetOne()
	zetaN.Exp(zeta, big.NewInt(int64(n)))
	zhZeta.Sub(&zetaN, &one)
	zn2.Mul(&zetaN, &zeta).Mul(&zn2, &zeta)

	// h1 + zeta^(n+2) h2 + zeta^(2(n+2)) h3, the part of h the linearized polynomial needs.
	hz := alloc(np2)
	memset0(hz, np2*fr.Bytes)
	coeff := one
	for i := 0; i < 3; i++ {
		axpy(hz, h.fr(i*np2), coeff, np2)
		coeff.Mul(&coeff, &zn2)
	}
	h.free()

	// Open Z (blinded) at zeta * omega.
	var zetaShifted fr.Element
	zetaShifted.Mul(&zeta, &p.vk.Generator)
	p.blindCoefficients(z, n, bp.z)
	var qz dvec
	proof.ZShiftedOpening.ClaimedValue, qz = p.divide(z, n+3, zetaShifted)
	proof.ZShiftedOpening.H = msm(qz, d.srs, n+2)
	qz.free()
	p.dropSrs(d)
	p.uploadState(d)

	// Interpolate all six polynomials at zeta with the same barycentric weights.
	tmp = alloc(n)
	p.qcpLagrange(d, tmp)
	var scale fr.Element
	scale.Mul(&zhZeta, &p.domain0.CardinalityInv)
	openings := lagrangeOpenings(d, tmp, n, p.u, p.u2, zeta, scale)
	for i, b := range [][]fr.Element{bp.l, bp.r, bp.o} {
		blind := evalPoly(b, zeta)
		blind.Mul(&blind, &zhZeta)
		openings[i].Add(&openings[i], &blind)
	}
	lZeta, rZeta, oZeta := openings[0], openings[1], openings[2]
	s1Zeta, s2Zeta, qcpZeta := openings[3], openings[4], openings[5]

	// The linearized polynomial, written over the blinded Z one term at a time.
	c := p.linearizationConstants(lZeta, rZeta, oZeta, s1Zeta, s2Zeta, alpha, beta, gamma, zeta, zetaN,
		proof.ZShiftedOpening.ClaimedValue)
	var zScale fr.Element
	zScale.Add(&c.s2, &c.a2l1)
	vscale(z, zScale, n+3)
	var mzh fr.Element
	mzh.Neg(&zhZeta)
	axpy(z, hz, mzh, np2)
	hz.free()
	p.uploadSrs(d)
	acc := alloc(n)
	memset0(acc, n*fr.Bytes)
	axpySource(acc, srcSigma(d.sigma.at(2*n, 4), d.tabW, p.u, p.u2), c.s1, n)
	for i, coeff := range []fr.Element{lZeta, rZeta, c.rl, oZeta, one} {
		axpySource(acc, srcExpand(d.selTab[i], d.sel[i]), coeff, n)
	}
	memset0(tmp, n*fr.Bytes)
	scatter(tmp, d.piPos, piVals)
	axpy(acc, tmp, qcpZeta, n)
	p.lagrangeCanonical(d, acc, nil)
	bitrev(acc, p.logN)
	vadd(z, acc, n)
	acc.free()
	tmp.free()
	p.waitUploads()
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
	tmp, acc = alloc(n), alloc(n)
	memset0(acc, n*fr.Bytes)
	for i, b := range [][]fr.Element{bp.l, bp.r, bp.o} {
		axpySource(acc, srcGather(d.values, d.wires.at(i*n, 4)), g, n)
		p.addBlindingTerms(z, n, g, b)
		g.Mul(&g, &foldGamma)
	}
	for i := range 2 {
		axpySource(acc, srcSigma(d.sigma.at(i*n, 4), d.tabW, p.u, p.u2), g, n)
		g.Mul(&g, &foldGamma)
	}
	p.qcpLagrange(d, tmp)
	axpy(acc, tmp, g, n)
	p.lagrangeCanonical(d, acc, nil)
	bitrev(acc, p.logN)
	vadd(z, acc, n)
	tmp.free()
	acc.free()
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

	var h dvec
	var saved [3]dvec
	const reserve = 256 << 20
	if free := freeMemory(); free >= uint64(3*n+8)*fr.Bytes+reserve {
		h = alloc(3*n + 8)
	} else if free > reserve {
		for i := range min(len(saved), int((free-reserve)/(uint64(n)*fr.Bytes))) {
			saved[i] = alloc(n)
		}
	}
	// A canonical polynomial is independent of the coset. Retain as many as
	// fit alongside the quotient workspace, starting with L (used twice per coset).
	available := freeMemory()
	var canonical [13]dvec // L, R, O, three permutations, five selectors, pi, qcp.
	if available > reserve && h.p != nil {
		count := min(len(canonical), int((available-reserve)/(uint64(n)*fr.Bytes)))
		for i := range count {
			canonical[i] = alloc(n)
		}
	}
	var ready [len(canonical)]bool
	var weights [4][4]fr.Element
	for k := 0; k < 4; k++ {
		c := p.cosets[k]
		var cn, cn1 fr.Element
		cn.Exp(c, big.NewInt(int64(n)))
		cn1.Sub(&cn, &one)
		blind := func(dst dvec, b []fr.Element) {
			r := make([]fr.Element, len(b))
			for i := range b {
				r[i].Mul(&b[i], &cn1)
			}
			blindCoset(dst, n, d.tabW, c, r)
		}
		evaluate := func(dst dvec, index int, makeCoeffs func(dvec)) {
			if cached := canonical[index]; cached.p != nil {
				if !ready[index] {
					makeCoeffs(cached)
					ready[index] = true
				}
				d2d(dst, cached, n*fr.Bytes)
			} else {
				makeCoeffs(dst)
			}
			nttDIT(dst, p.logN, d.tabW, d.tabC[k])
		}
		lro := func(dst dvec, j int, b []fr.Element) {
			evaluate(dst, j, func(v dvec) { p.lroCanonical(d, v, j) })
			blind(dst, b)
		}
		sel := func(dst dvec, i int, overrides []fr.Element) {
			evaluate(dst, 6+i, func(v dvec) { p.selectorCanonical(d, v, i, overrides) })
		}
		sigma := func(dst dvec, j int) {
			evaluate(dst, 3+j, func(v dvec) { p.sCanonical(d, v, j) })
		}

		// Gate constraint, with x, y, t holding l, r, o.
		lro(x, 0, bp.l)
		lro(y, 1, bp.r)
		lro(t, 2, bp.o)
		sel(sv, 0, nil)
		if h.p == nil && k > 0 {
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

		if z.p != nil {
			p.cosetEval(d, sv, z, k)
		} else {
			if k < len(p.hostG) {
				h2dElements(sv, p.hostG[2])
			} else {
				p.zCanonical(d, sv, beta, gamma)
			}
			p.cosetEval(d, sv, sv, k)
		}
		blind(sv, bp.z)
		var a2l1 fr.Element
		a2l1.Square(&alpha).Mul(&a2l1, &cn1).Mul(&a2l1, &nInv)
		zCombine(a, x, y, sv, n, d.tabW, c, alpha, a2l1)

		// The bsb22 commitment's gate term.
		evaluate(x, 11, func(v dvec) { p.sparseCanonical(d, v, d.piPos, piVals) })
		evaluate(y, 12, func(v dvec) { p.qcpCanonical(d, v) })
		vfma(a, x, y, n)

		// The bit-reversed coefficients of g(c_k X), which hAccum turns into those of g.
		p.lagrangeCanonical(d, a, nil)

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
		if h.p != nil {
			hAccum(h, a, n, d.tabCInv[k], weights[k], k == 0)
		} else if k < len(saved) {
			if saved[k].p != nil {
				a, saved[k] = saved[k], a
			} else {
				after(p.copyStream, nil, p.computeDone)
				d2hAsync(unsafe.Pointer(&p.hostBuffer(k)[0]), a, n*fr.Bytes, p.copyStream)
			}
		}
	}
	for _, v := range canonical {
		if v.p != nil {
			v.free()
		}
	}
	for _, b := range []dvec{x, y, t, sv} {
		b.free()
	}

	if h.p == nil {
		syncStream(p.copyStream)
		h = alloc(3*n + 8)
		hAccum(h, a, n, d.tabCInv[3], weights[3], true)
		for k := 0; k < 3; k++ {
			src := saved[k]
			if src.p == nil {
				h2d(a, unsafe.Pointer(&p.hostG[k][0]), n*fr.Bytes)
				src = a
			}
			hAccum(h, src, n, d.tabCInv[k], weights[k], false)
			if saved[k].p != nil {
				saved[k].free()
			}
		}
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
	s1, s2, rl, a2l1 fr.Element
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
