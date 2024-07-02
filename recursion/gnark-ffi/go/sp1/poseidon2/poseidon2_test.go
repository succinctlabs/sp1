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
		frontend.Variable("0x2ED1DA00B14D635BD35B88AB49390D5C13C90DA7E9E3A5F1EA69CD87A0AA3E82"),
		frontend.Variable("0x1E21E979CC3FD844B88C2016FD18F4DB07A698AA27DECA67CA509F5B0A4480D0"),
		frontend.Variable("0x2C40D0115DA2C9B55553B231BE55295F411E628ED0CD0E187917066515F0A060"),
	}

	circuit = TestPoseidon2Circuit{Input: input, ExpectedOutput: expected_output}
	witness = TestPoseidon2Circuit{Input: input, ExpectedOutput: expected_output}
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.PLONK))
}
