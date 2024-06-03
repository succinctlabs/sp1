package sp1

import (
	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1/babybear"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1/poseidon2"
)

type TestPoseidon2BabyBearCircuit struct {
	Input          [poseidon2.BABYBEAR_WIDTH]babybear.Variable `gnark:",public"`
	ExpectedOutput [poseidon2.BABYBEAR_WIDTH]babybear.Variable `gnark:",public"`
}

func (circuit *TestPoseidon2BabyBearCircuit) Define(api frontend.API) error {
	poseidon2BabyBearChip := poseidon2.NewPoseidon2BabyBearChip(api)

	input := [poseidon2.BABYBEAR_WIDTH]babybear.Variable{}
	for i := 0; i < poseidon2.BABYBEAR_WIDTH; i++ {
		input[i] = circuit.Input[i]
	}

	poseidon2BabyBearChip.PermuteMut(&input)

	fieldApi := babybear.NewChip(api)
	for i := 0; i < poseidon2.BABYBEAR_WIDTH; i++ {
		fieldApi.AssertIsEqualF(circuit.ExpectedOutput[i], input[i])
	}

	return nil
}
