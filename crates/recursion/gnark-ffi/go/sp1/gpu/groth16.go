//go:build cuda

package gpu

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"math/bits"
	"runtime"
	"slices"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/hash_to_field"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	fcs "github.com/consensys/gnark/frontend/cs"
)

// Groth16Prover holds one circuit's proving key in host memory.
type Groth16Prover struct {
	r1cs                         *cs.R1CS
	solver                       *levelSolver
	pk                           *groth16_bn254.ProvingKey
	files                        groth16KeyFiles
	logN                         int
	tabW, tabWInv, tabC, tabCInv []fr.Element
}

// A native gnark dump stores these affine tables uncompressed.
type groth16KeyFiles struct {
	a, b, z, k, b2 *io.SectionReader
}

// ReadDump allocates the final slices before reading their native bytes. Leave
// large tables file-backed and check their destination and length after decoding.
type dumpReader struct {
	source   *io.SectionReader
	pk       *groth16_bn254.ProvingKey
	pos      int64
	elements uint64
	tables   map[*byte]*io.SectionReader
}

func (r *dumpReader) Read(b []byte) (int, error) {
	size := uint64(len(b))
	if size >= 64<<20 && r.elements != 0 && size%r.elements == 0 &&
		r.pk.InfinityB != nil && r.pk.G2.B == nil && int64(size) <= r.source.Size()-r.pos {
		switch size / r.elements {
		case uint64(unsafe.Sizeof(curve.G1Affine{})), uint64(unsafe.Sizeof(curve.G2Affine{})):
			r.tables[&b[0]] = io.NewSectionReader(r.source, r.pos, int64(size))
			r.pos += int64(size)
			r.elements = 0
			return len(b), nil
		}
	}
	n, err := r.source.ReadAt(b, r.pos)
	r.pos += int64(n)
	r.elements = 0
	if n == 8 && n == len(b) {
		r.elements = binary.LittleEndian.Uint64(b)
	}
	return n, err
}

func takeDumpTable[T any](r *dumpReader, points *[]T) *io.SectionReader {
	if len(*points) == 0 {
		return nil
	}
	first := (*byte)(unsafe.Pointer(&(*points)[0]))
	table := r.tables[first]
	if table == nil || table.Size() != int64(len(*points))*int64(unsafe.Sizeof((*points)[0])) {
		return nil
	}
	delete(r.tables, first)
	*points = nil
	return table
}

// NewGroth16Prover reads a native gnark key. A section reader at the start of an
// immutable key must stay available for the prover lifetime and permits streamed MSMs.
func NewGroth16Prover(r1cs *cs.R1CS, r io.Reader) (*Groth16Prover, error) {
	// Debug info only describes failed constraints in errors.
	r1cs.DebugInfo, r1cs.MDebug = nil, nil
	solver, err := newR1CSSolver(r1cs)
	if err != nil {
		return nil, err
	}
	// Lets the key reuse the memory of the calldata that the solver freed.
	runtime.GC()
	pk := &groth16_bn254.ProvingKey{}
	var dump *dumpReader
	if source, ok := r.(*io.SectionReader); ok {
		if pos, err := source.Seek(0, io.SeekCurrent); err == nil && pos == 0 {
			dump = &dumpReader{source: source, pk: pk, tables: make(map[*byte]*io.SectionReader)}
			r = dump
		}
	}
	err = pk.ReadDump(r)
	var files groth16KeyFiles
	if dump != nil {
		if err == nil {
			files.a = takeDumpTable(dump, &pk.G1.A)
			files.b = takeDumpTable(dump, &pk.G1.B)
			files.z = takeDumpTable(dump, &pk.G1.Z)
			files.k = takeDumpTable(dump, &pk.G1.K)
			files.b2 = takeDumpTable(dump, &pk.G2.B)
		}
		if len(dump.tables) != 0 {
			// A different decoder layout needs the ordinary, fully populated key.
			files = groth16KeyFiles{}
			pk = &groth16_bn254.ProvingKey{}
			err = pk.ReadDump(io.NewSectionReader(dump.source, 0, dump.source.Size()))
		}
	}
	if err != nil {
		return nil, err
	}
	d := &pk.Domain
	// The kernels use their own power tables, so the domain's precomputed ones are dropped.
	*d = fft.Domain{
		Cardinality: d.Cardinality, CardinalityInv: d.CardinalityInv,
		Generator: d.Generator, GeneratorInv: d.GeneratorInv,
		FrMultiplicativeGen: d.FrMultiplicativeGen, FrMultiplicativeGenInv: d.FrMultiplicativeGenInv,
	}
	var gInv fr.Element
	gInv.Inverse(&d.FrMultiplicativeGen)
	p := &Groth16Prover{
		r1cs: r1cs, solver: solver, pk: pk, files: files, logN: bits.TrailingZeros64(d.Cardinality),
		tabW: powTable(d.Generator), tabWInv: powTable(d.GeneratorInv),
		tabC: powTable(d.FrMultiplicativeGen), tabCInv: powTable(gInv),
	}
	for _, v := range [][]curve.G1Affine{pk.G1.A, pk.G1.B, pk.G1.K, pk.G1.Z} {
		if len(v) > 0 {
			pin(v)
		}
	}
	if len(pk.G2.B) != 0 {
		pin(pk.G2.B)
	}
	for _, k := range pk.CommitmentKeys {
		pin(k.Basis)
		pin(k.BasisExpSigma)
	}
	return p, nil
}

// Prove computes a Groth16 proof for the given full witness.
func (p *Groth16Prover) Prove(fullWitness witness.Witness) (*groth16_bn254.Proof, error) {
	values, ok := fullWitness.Vector().(fr.Vector)
	if !ok {
		return nil, fmt.Errorf("gpu: expected a BN254 witness")
	}
	return p.ProveVector(values)
}

// ProveVector accepts the public and secret wires in gnark witness order.
func (p *Groth16Prover) ProveVector(fullWitness fr.Vector) (proof *groth16_bn254.Proof, err error) {
	defer freeAll()
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("gpu: %v", r)
		}
	}()
	pk := p.pk
	commitmentInfo := p.r1cs.CommitmentInfo.(constraint.Groth16Commitments)
	proof = &groth16_bn254.Proof{Commitments: make([]curve.G1Affine, len(commitmentInfo))}

	privateCommittedValues := make([][]fr.Element, len(commitmentInfo))
	htf := hash_to_field.New([]byte(constraint.CommitmentDst))
	hint := solver.OverrideHint(solver.GetHintID(fcs.Bsb22CommitmentComputePlaceholder), func(_ *big.Int, in, out []*big.Int) (err error) {
		// The hint runs on a solver goroutine, out of reach of Prove's recover.
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("bsb22 commitment: %v", r)
			}
		}()
		i := int(in[0].Int64())
		in = in[1:]
		privateCommittedValues[i] = make([]fr.Element, len(commitmentInfo[i].PrivateCommitted))
		hashed := in[:len(commitmentInfo[i].PublicAndCommitmentCommitted)]
		for j, v := range in[len(hashed):] {
			privateCommittedValues[i][j].SetBigInt(v)
		}
		if len(privateCommittedValues[i]) != len(pk.CommitmentKeys[i].Basis) {
			return fmt.Errorf("must have as many values as basis elements")
		}
		proof.Commitments[i] = msmHost(pk.CommitmentKeys[i].Basis, privateCommittedValues[i])
		htf.Write(constraint.SerializeCommitment(proof.Commitments[i].Marshal(), hashed, (fr.Bits-1)/8+1))
		hashBts := htf.Sum(nil)
		htf.Reset()
		var res fr.Element
		res.SetBytes(hashBts[:min(fr.Bytes, htf.Size())])
		res.BigInt(out[0])
		return nil
	})
	defer func() { p.solver.values = nil }()
	if err := p.solver.solve(fullWitness, hint); err != nil {
		return nil, err
	}
	wireValues := p.solver.values

	poks := make([]curve.G1Affine, len(pk.CommitmentKeys))
	for i := range pk.CommitmentKeys {
		poks[i] = msmHost(pk.CommitmentKeys[i].BasisExpSigma, privateCommittedValues[i])
	}
	commitmentsSerialized := make([]byte, fr.Bytes*len(commitmentInfo))
	for i := range commitmentInfo {
		copy(commitmentsSerialized[fr.Bytes*i:], wireValues[commitmentInfo[i].CommitmentIndex].Marshal())
	}
	challenge, err := fr.Hash(commitmentsSerialized, []byte("G16-BSB22"), 1)
	if err != nil {
		return nil, err
	}
	if _, err = proof.CommitmentPok.Fold(poks, challenge[0], ecc.MultiExpConfig{NbTasks: 1}); err != nil {
		return nil, err
	}

	h := p.computeH()
	scalars := make([]fr.Element, 0, len(wireValues))

	var r, s big.Int
	var _r, _s, _kr fr.Element
	if _, err := _r.SetRandom(); err != nil {
		return nil, err
	}
	if _, err := _s.SetRandom(); err != nil {
		return nil, err
	}
	_kr.Mul(&_r, &_s).Neg(&_kr)
	_r.BigInt(&r)
	_s.BigInt(&s)
	deltas := curve.BatchScalarMultiplicationG1(&pk.G1.Delta, []fr.Element{_r, _s, _kr})

	sizeH := int(pk.Domain.Cardinality - 1) // deg(H) = (n-1) + (n-1) - n = n-2
	z := uploadKeyPoints(pk.G1.Z, p.files.z, sizeH)
	krs2 := msm(h, z, sizeH)
	z.free()
	h.free()

	scalars = withoutInfinity(scalars, wireValues, pk.InfinityA)
	var ar curve.G1Jac
	a := msmKeyPoints(pk.G1.A, p.files.a, scalars)
	ar.FromAffine(&a)
	ar.AddMixed(&pk.G1.Alpha)
	ar.AddMixed(&deltas[0])
	proof.Ar.FromJacobian(&ar)

	scalars = withoutInfinity(scalars, wireValues, pk.InfinityB)
	var bs1 curve.G1Jac
	b1 := msmKeyPoints(pk.G1.B, p.files.b, scalars)
	bs1.FromAffine(&b1)
	bs1.AddMixed(&pk.G1.Beta)
	bs1.AddMixed(&deltas[1])

	var bs, deltaS curve.G2Jac
	b2 := msmHostG2(pk.G2.B, p.files.b2, scalars)
	bs.FromAffine(&b2)
	deltaS.FromAffine(&pk.G2.Delta)
	deltaS.ScalarMultiplication(&deltaS, &s)
	bs.AddAssign(&deltaS)
	bs.AddMixed(&pk.G2.Beta)
	proof.Bs.FromJacobian(&bs)

	var toRemove []int
	for _, c := range commitmentInfo.GetPrivateCommitted() {
		toRemove = append(toRemove, c...)
	}
	toRemove = append(toRemove, commitmentInfo.CommitmentIndexes()...)
	nbPub := p.r1cs.GetNbPublicVariables()
	var krs, p1 curve.G1Jac
	slices.Sort(toRemove)
	k := msmKeyPoints(pk.G1.K, p.files.k, without(scalars, wireValues[nbPub:], nbPub, toRemove))
	krs.FromAffine(&k)
	krs.AddMixed(&deltas[2])
	krs.AddMixed(&krs2)
	p1.ScalarMultiplication(&ar, &s)
	krs.AddAssign(&p1)
	p1.ScalarMultiplication(&bs1, &r)
	krs.AddAssign(&p1)
	proof.Krs.FromJacobian(&krs)
	return proof, nil
}

// computeH returns the coefficients of (a*b - c) / (X^n - 1) in bit-reversed order, as gnark does.
func (p *Groth16Prover) computeH() dvec {
	d := &p.pk.Domain
	n := int(d.Cardinality)
	tabW, tabWInv, tabC, tabCInv := upload(p.tabW), upload(p.tabWInv), upload(p.tabC), upload(p.tabCInv)
	var den, one fr.Element
	one.SetOne()
	den.Exp(d.FrMultiplicativeGen, big.NewInt(int64(n)))
	den.Sub(&den, &one).Inverse(&den)

	v := [3]dvec{alloc(n), alloc(n), alloc(n)}
	// The checked witness determines both inputs and their product on every R1CS row.
	qapRows(v, p.solver, n)
	for i := range v {
		ntt(v[i], p.logN, tabWInv, &d.CardinalityInv)
		scalePow(v[i], v[i], n, tabC)
		ntt(v[i], p.logN, tabW, nil)
	}
	vmul(v[0], v[0], v[1], n)
	vsub(v[0], v[2], n)
	vscale(v[0], den, n)
	v[1].free()
	v[2].free()
	ntt(v[0], p.logN, tabWInv, &d.CardinalityInv)
	scalePow(v[0], v[0], n, tabCInv)
	bitrev(v[0], p.logN)
	for _, t := range []dvec{tabW, tabWInv, tabC, tabCInv} {
		t.free()
	}
	return v[0]
}

// withoutInfinity overwrites dst with the elements of v whose point is not at infinity.
func withoutInfinity(dst, v []fr.Element, infinity []bool) []fr.Element {
	r := dst[:0]
	for i := range v {
		if !infinity[i] {
			r = append(r, v[i])
		}
	}
	return r
}

// without copies the runs between the sorted wire indices to remove.
func without(dst, v []fr.Element, first int, remove []int) []fr.Element {
	r := dst[:0]
	start := 0
	for _, wire := range remove {
		i := wire - first
		if i < start {
			continue
		}
		if i >= len(v) {
			break
		}
		r = append(r, v[start:i]...)
		start = i + 1
	}
	return append(r, v[start:]...)
}
