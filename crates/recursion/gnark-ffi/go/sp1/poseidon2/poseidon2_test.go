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
		frontend.Variable("0x02A874754DC3A41A8991C7BF3D0655233870DD9328FC83FA792C56D70FA65A88"),
		frontend.Variable("0x0C1B4CCAA98CD30A990D116A0DEE44E246CBFE259D35B41A4723843BFF468ED6"),
		frontend.Variable("0x11D9CC66E6F5DC031F61F4B05233BB5F9E948FE0514F43F6EAFD9609CF2C1C67"),
	}

	circuit = TestPoseidon2Circuit{Input: input, ExpectedOutput: expected_output}
	witness = TestPoseidon2Circuit{Input: input, ExpectedOutput: expected_output}
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BLS12_377), test.WithBackends(backend.PLONK))
}
