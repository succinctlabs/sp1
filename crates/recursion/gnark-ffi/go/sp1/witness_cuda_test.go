//go:build cuda

package sp1

import (
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
)

func TestWitnessVectorMatchesGnark(t *testing.T) {
	in := WitnessInput{
		VkeyHash: "11", CommittedValuesDigest: "13", ExitCode: "0", VkRoot: "17", ProofNonce: "19",
		Vars: []string{"10000000000", "23"}, Felts: []string{"0", "2130706432"},
		Exts: [][]string{{"1", "2", "3", "4"}, {"5", "6", "7", "8"}},
	}
	assignment := NewCircuit(in)
	reference, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	got, err := WitnessVector(in)
	if err != nil || !slices.Equal(got, reference.Vector().(fr.Vector)) {
		t.Fatalf("direct witness differs from gnark: %v", err)
	}
	in.Exts[0] = in.Exts[0][:3]
	if _, err := WitnessVector(in); err == nil {
		t.Fatal("accepted a truncated extension-field witness")
	}
}
