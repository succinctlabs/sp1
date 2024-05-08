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
	"github.com/succinctlabs/sp1-recursion-gnark/sp1"
)

func TestMain(t *testing.T) {
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

	// Compile the circuit.
	circuit := sp1.NewCircuit(inputs)
	builder := r1cs.NewBuilder
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	if err != nil {
		panic(err)
	}
	fmt.Println("[sp1] groth16 verifier constraints:", r1cs.GetNbConstraints())

	// Run the dummy setup.
	var pk groth16.ProvingKey
	pk, err = groth16.DummySetup(r1cs)
	if err != nil {
		panic(err)
	}

	// Generate witness.
	assignment := sp1.NewCircuit(inputs)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	// Generate the proof.
	_, err = groth16.Prove(r1cs, pk, witness)
	if err != nil {
		panic(err)
	}

}
