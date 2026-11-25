//go:build cuda

package gpu

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
)

func TestLagrangeOpenings(t *testing.T) {
	for _, n := range []int{16, 256} {
		domain := fft.NewDomain(uint64(n))
		u := domain.FrMultiplicativeGen
		var u2 fr.Element
		u2.Square(&u)
		values, roots, qcp := make([]fr.Element, n), make([]fr.Element, n), make([]fr.Element, n)
		roots[0].SetOne()
		for i := range n {
			values[i].SetUint64(uint64(i*i + 3))
			if i > 0 {
				roots[i].Mul(&roots[i-1], &domain.Generator)
			}
			if i%7 == 0 {
				qcp[i].SetOne()
			}
		}
		wires, sigma := make([]uint32, 3*n), make([]uint32, 2*n)
		var polys [6][]fr.Element
		for j := range polys {
			polys[j] = make([]fr.Element, n)
			for i := range n {
				switch j {
				case 0, 1, 2:
					wire := (5*i + 11*j) % n
					wires[j*n+i] = uint32(wire)
					polys[j][i] = values[wire]
				case 3, 4:
					index := (13*i + 17 + (j-3)*n) % (3 * n)
					sigma[(j-3)*n+i] = uint32(index)
					coset := [3]fr.Element{fr.One(), u, u2}
					polys[j][i].Mul(&roots[index%n], &coset[index/n])
				case 5:
					polys[j][i] = qcp[i]
				}
			}
			domain.FFTInverse(polys[j], fft.DIF)
			fft.BitReverse(polys[j])
		}

		d := &device{values: upload(values), wires: upload(wires), sigma: upload(sigma), tabW: upload(powTable(domain.Generator))}
		q := upload(qcp)
		for _, z := range []fr.Element{fr.NewElement(2), roots[7]} {
			var scale fr.Element
			one := fr.One()
			scale.Exp(z, big.NewInt(int64(n))).Sub(&scale, &one).Mul(&scale, &domain.CardinalityInv)
			got := lagrangeOpenings(d, q, n, u, u2, z, scale)
			for j, poly := range polys {
				want := evalPoly(poly, z)
				if got[j] != want {
					t.Errorf("size %d column %d at %s: got %s, want %s", n, j, z.String(), got[j].String(), want.String())
				}
			}
		}
		freeAll()
	}
}
