package main

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/succinctlabs/sp1-recursion-gnark/babybear_v2"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1"
)

func TestMain(t *testing.T) {
	// assert := test.NewAssert(t)

	// Get the file name from an environment variable.
	fileName := os.Getenv("WITNESS_JSON")
	if fileName == "" {
		fileName = "witness.json"
	}

	// Read the file.
	data, err := os.ReadFile(fileName)
	if err != nil {
		panic(err)
	}

	// Deserialize the JSON data into a slice of Instruction structs
	var inputs sp1.WitnessInput
	err = json.Unmarshal(data, &inputs)
	if err != nil {
		panic(err)
	}

	vars := make([]frontend.Variable, len(inputs.Vars))
	felts := make([]babybear_v2.Variable, len(inputs.Felts))
	exts := make([]babybear_v2.ExtensionVariable, len(inputs.Exts))
	for i := 0; i < len(inputs.Vars); i++ {
		vars[i] = frontend.Variable(inputs.Vars[i])
	}
	for i := 0; i < len(inputs.Felts); i++ {
		felts[i] = babybear_v2.NewF(inputs.Felts[i])
	}
	for i := 0; i < len(inputs.Exts); i++ {
		exts[i] = babybear_v2.NewE(inputs.Exts[i])
	}

	// Run some sanity checks.
	circuit := sp1.Circuit{
		Vars:                 vars,
		Felts:                felts,
		Exts:                 exts,
		VkeyHash:             inputs.VkeyHash,
		CommitedValuesDigest: inputs.CommitedValuesDigest,
	}

	// Compile the circuit.
	builder := r1cs.NewBuilder
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	if err != nil {
		panic(err)
	}
	fmt.Println("NbConstraints:", r1cs.GetNbConstraints())

	// Run the dummy setup.
	var pk groth16.ProvingKey
	pk, err = groth16.DummySetup(r1cs)
	if err != nil {
		panic(err)
	}

	// Generate witness.
	vars = make([]frontend.Variable, len(inputs.Vars))
	felts = make([]babybear_v2.Variable, len(inputs.Felts))
	exts = make([]babybear_v2.ExtensionVariable, len(inputs.Exts))
	for i := 0; i < len(inputs.Vars); i++ {
		vars[i] = frontend.Variable(inputs.Vars[i])
	}
	for i := 0; i < len(inputs.Felts); i++ {
		felts[i] = babybear_v2.NewF(inputs.Felts[i])
	}
	for i := 0; i < len(inputs.Exts); i++ {
		exts[i] = babybear_v2.NewE(inputs.Exts[i])
	}
	assignment := sp1.Circuit{
		Vars:                 vars,
		Felts:                felts,
		Exts:                 exts,
		VkeyHash:             inputs.VkeyHash,
		CommitedValuesDigest: inputs.CommitedValuesDigest,
	}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	// Generate the proof.
	_, err = groth16.Prove(r1cs, pk, witness)
	if err != nil {
		panic(err)
	}

	// This was the old way we were testing the circuit, but it seems to have edge cases where it
	// doesn't properly check that the prover will succeed.
	//
	// assert.CheckCircuit(&circuit, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}
