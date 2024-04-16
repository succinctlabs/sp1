package main

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/succinctlabs/sp1-recursion-groth16/babybear"
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
	var witness Witness
	err = json.Unmarshal(data, &witness)
	if err != nil {
		panic(err)
	}

	vars := make([]frontend.Variable, len(witness.Vars))
	felts := make([]*babybear.Variable, len(witness.Felts))
	exts := make([]*babybear.ExtensionVariable, len(witness.Exts))
	for i := 0; i < len(witness.Vars); i++ {
		vars[i] = frontend.Variable(witness.Vars[i])
	}
	for i := 0; i < len(witness.Felts); i++ {
		felts[i] = babybear.NewF(witness.Felts[i])
	}
	for i := 0; i < len(witness.Exts); i++ {
		exts[i] = babybear.NewE(witness.Exts[i])
	}

	// Run some sanity checks.
	circuit := Circuit{
		Vars:  vars,
		Felts: felts,
		Exts:  exts,
	}

	// Compile the circuit.
	start := time.Now()
	builder := r1cs.NewBuilder
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	fmt.Printf("compilation took %s\n", elapsed)
	fmt.Println("NbConstraints:", r1cs.GetNbConstraints())

	// Generate the witness.
	start = time.Now()
	assignment, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	elapsed = time.Since(start)
	fmt.Printf("witness gen took %s\n", elapsed)

	// Run the dummy setup.
	var pk groth16.ProvingKey
	pk, err = groth16.DummySetup(r1cs)
	if err != nil {
		t.Fatal(err)
	}

	// Generate the proof.
	start = time.Now()
	proof, err := groth16.Prove(r1cs, pk, assignment)
	if err != nil {
		t.Fatal(err)
	}
	elapsed = time.Since(start)
	fmt.Printf("proving took %s\n", elapsed)
	fmt.Println(proof)
}
