//go:build cuda

package gpu

import (
	"fmt"
	"math/big"
	"math/bits"
	"slices"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
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
	pk                           *groth16_bn254.ProvingKey
	logN                         int
	tabW, tabWInv, tabC, tabCInv []fr.Element
}

// NewGroth16Prover page-locks the proving key's points, which are uploaded for each proof.
func NewGroth16Prover(r1cs *cs.R1CS, pk *groth16_bn254.ProvingKey) *Groth16Prover {
	d := &pk.Domain
	var gInv fr.Element
	gInv.Inverse(&d.FrMultiplicativeGen)
	p := &Groth16Prover{
		r1cs: r1cs, pk: pk, logN: bits.TrailingZeros64(d.Cardinality),
		tabW: powTable(d.Generator), tabWInv: powTable(d.GeneratorInv),
		tabC: powTable(d.FrMultiplicativeGen), tabCInv: powTable(gInv),
	}
	for _, v := range [][]curve.G1Affine{pk.G1.A, pk.G1.B, pk.G1.K, pk.G1.Z} {
		pin(v)
	}
	pin(pk.G2.B)
	for _, k := range pk.CommitmentKeys {
		pin(k.Basis)
		pin(k.BasisExpSigma)
	}
	return p
}

// Prove computes a Groth16 proof for the given full witness.
func (p *Groth16Prover) Prove(fullWitness witness.Witness) (proof *groth16_bn254.Proof, err error) {
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
	_solution, err := p.r1cs.Solve(fullWitness, hint)
	if err != nil {
		return nil, err
	}
	solution := _solution.(*cs.R1CSSolution)
	wireValues := []fr.Element(solution.W)

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

	h := p.computeH(solution.A, solution.B, solution.C)
	solution.A, solution.B, solution.C = nil, nil, nil

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
	z := upload(pk.G1.Z[:sizeH])
	krs2 := msm(h, z, sizeH)
	z.free()
	h.free()

	wireValuesA := withoutInfinity(wireValues, pk.InfinityA, pk.NbInfinityA)
	var ar curve.G1Jac
	a := msmHost(pk.G1.A, wireValuesA)
	ar.FromAffine(&a)
	ar.AddMixed(&pk.G1.Alpha)
	ar.AddMixed(&deltas[0])
	proof.Ar.FromJacobian(&ar)

	wireValuesB := withoutInfinity(wireValues, pk.InfinityB, pk.NbInfinityB)
	var bs1 curve.G1Jac
	b1 := msmHost(pk.G1.B, wireValuesB)
	bs1.FromAffine(&b1)
	bs1.AddMixed(&pk.G1.Beta)
	bs1.AddMixed(&deltas[1])

	var bs, deltaS curve.G2Jac
	b2 := msmHostG2(pk.G2.B, wireValuesB)
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
	k := msmHost(pk.G1.K, without(wireValues[nbPub:], nbPub, toRemove))
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
func (p *Groth16Prover) computeH(a, b, c []fr.Element) dvec {
	d := &p.pk.Domain
	n := int(d.Cardinality)
	tabW, tabWInv, tabC, tabCInv := upload(p.tabW), upload(p.tabWInv), upload(p.tabC), upload(p.tabCInv)
	var den, one fr.Element
	one.SetOne()
	den.Exp(d.FrMultiplicativeGen, big.NewInt(int64(n)))
	den.Sub(&den, &one).Inverse(&den)

	var v [3]dvec
	for i, host := range [][]fr.Element{a, b, c} {
		v[i] = alloc(n)
		memset0(v[i], n*fr.Bytes)
		h2dElements(v[i], host)
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

func withoutInfinity(v []fr.Element, infinity []bool, nbInfinity uint64) []fr.Element {
	r := make([]fr.Element, 0, len(v)-int(nbInfinity))
	for i := range v {
		if !infinity[i] {
			r = append(r, v[i])
		}
	}
	return r
}

// without returns v without the elements whose index plus first is in remove.
func without(v []fr.Element, first int, remove []int) []fr.Element {
	remove = slices.Clone(remove)
	slices.Sort(remove)
	r := make([]fr.Element, 0, len(v))
	for i := range v {
		if _, found := slices.BinarySearch(remove, i+first); !found {
			r = append(r, v[i])
		}
	}
	return r
}
