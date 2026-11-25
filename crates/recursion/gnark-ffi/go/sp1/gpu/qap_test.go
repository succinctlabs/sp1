//go:build cuda

package gpu

import (
	"encoding/binary"
	"testing"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	cs "github.com/consensys/gnark/constraint/bn254"
)

func TestQAPFromPackedTerms(t *testing.T) {
	t.Cleanup(freeAll)
	s := &levelSolver{
		SparseR1CS: cs.NewR1CS(0), values: make([]fr.Element, 47),
		termWidth: 2, cBits: 3, termStart: []uint32{0, 5, 8},
	}
	s.Coefficients = make([]fr.Element, 6)
	for i, c := range []int64{0, 1, 2, -1, -2, 7} {
		s.Coefficients[i].SetInt64(c)
	}
	s.values[0].SetOne()
	s.values[43].SetUint64(3)
	s.values[7].SetUint64(4)
	s.values[46].SetUint64(160)
	for _, term := range []struct{ wire, coeff, side uint16 }{
		{43, 5, 0}, {0, 3, 0}, {7, 2, 1}, {45, 0, 1}, {46, 1, 2},
		{0, 2, 0}, {0, 4, 0}, {0, 1, 1},
	} {
		s.terms = binary.LittleEndian.AppendUint16(s.terms, term.wire<<5|term.coeff<<2|term.side)
	}

	const n = 4
	v := [3]dvec{alloc(n), alloc(n), alloc(n)}
	qapRows(v, s, n)
	var got [3][n]fr.Element
	for j := range v {
		d2h(unsafe.Pointer(&got[j][0]), v[j], n*fr.Bytes)
	}
	deviceSync()
	// The first row is (7*3 - 1) * (2*4) = 160. The second is (2 - 2) * 1 = 0.
	for j, want := range [3][n]uint64{{20, 0, 0, 0}, {8, 1, 0, 0}, {160, 0, 0, 0}} {
		for i, scalar := range want {
			if got[j][i] != fr.NewElement(scalar) {
				t.Errorf("column %d row %d: got %s, want %d", j, i, got[j][i].String(), scalar)
			}
		}
	}
}
