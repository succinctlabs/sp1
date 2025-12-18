package poseidon2

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type TestPoseidon2Circuit struct {
	Input, ExpectedOutput [width]frontend.Variable `gnark:",public"`
}

func (circuit *TestPoseidon2Circuit) Define(api frontend.API) error {
	poseidon2Chip := NewChip(api)

	input := [width]frontend.Variable{}
	for i := 0; i < width; i++ {
		input[i] = circuit.Input[i]
	}

	poseidon2Chip.PermuteMut(&input)

	for i := 0; i < width; i++ {
		api.AssertIsEqual(circuit.ExpectedOutput[i], input[i])
	}

	return nil
}

func TestPoseidon2(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit, witness TestPoseidon2Circuit

	input := [width]frontend.Variable{
		frontend.Variable(0),
		frontend.Variable(0),
		frontend.Variable(0),
	}

	expected_output := [width]frontend.Variable{
		frontend.Variable("0x073A16E09D72EB3CE2BE32D26298E581FE6D6F5C50DF62B35C7ED36BED69B06A"),
		frontend.Variable("0x0646CF2FA3846E5B849972B65A44D33CBC30112153515071103EB6D8B162A187"),
		frontend.Variable("0x11781011359B52E0D8AE583C071D5F487A1B06D5F64E755A7BD893C27A827C25"),
	}

	circuit = TestPoseidon2Circuit{Input: input, ExpectedOutput: expected_output}
	witness = TestPoseidon2Circuit{Input: input, ExpectedOutput: expected_output}
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BLS12_377), test.WithBackends(backend.PLONK))
}
