package poseidon2

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1/babybear"
)

type TestPoseidon2BabyBearCircuit struct {
	Input, ExpectedOutput [BABYBEAR_WIDTH]babybear.Variable `gnark:",public"`
}

func (circuit *TestPoseidon2BabyBearCircuit) Define(api frontend.API) error {
	poseidon2BabyBearChip := NewPoseidon2BabyBearChip(api)

	input := [BABYBEAR_WIDTH]babybear.Variable{}
	for i := 0; i < BABYBEAR_WIDTH; i++ {
		input[i] = circuit.Input[i]
	}

	poseidon2BabyBearChip.PermuteMut(&input)

	fieldApi := babybear.NewChip(api)
	for i := 0; i < BABYBEAR_WIDTH; i++ {
		fieldApi.AssertIsEqualF(circuit.ExpectedOutput[i], input[i])
	}

	return nil
}

func TestPoseidonBabyBear2(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit, witness TestPoseidon2BabyBearCircuit

	input := [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("894848333"),
		babybear.NewF("1437655012"),
		babybear.NewF("1200606629"),
		babybear.NewF("1690012884"),
		babybear.NewF("71131202"),
		babybear.NewF("1749206695"),
		babybear.NewF("1717947831"),
		babybear.NewF("120589055"),
		babybear.NewF("19776022"),
		babybear.NewF("42382981"),
		babybear.NewF("1831865506"),
		babybear.NewF("724844064"),
		babybear.NewF("171220207"),
		babybear.NewF("1299207443"),
		babybear.NewF("227047920"),
		babybear.NewF("1783754913"),
	}

	expected_output := [BABYBEAR_WIDTH]babybear.Variable{
		babybear.NewF("512585766"),
		babybear.NewF("975869435"),
		babybear.NewF("1921378527"),
		babybear.NewF("1238606951"),
		babybear.NewF("899635794"),
		babybear.NewF("132650430"),
		babybear.NewF("1426417547"),
		babybear.NewF("1734425242"),
		babybear.NewF("57415409"),
		babybear.NewF("67173027"),
		babybear.NewF("1535042492"),
		babybear.NewF("1318033394"),
		babybear.NewF("1070659233"),
		babybear.NewF("17258943"),
		babybear.NewF("856719028"),
		babybear.NewF("1500534995"),
	}

	circuit = TestPoseidon2BabyBearCircuit{Input: input, ExpectedOutput: expected_output}
	witness = TestPoseidon2BabyBearCircuit{Input: input, ExpectedOutput: expected_output}
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.PLONK))
}
