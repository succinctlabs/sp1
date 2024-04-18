package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/succinctlabs/sp1-recursion-groth16/babybear"
)

func TestMain(t *testing.T) {
	assert := test.NewAssert(t)

	// // Initialize the circuit.
	// var circuit Circuit

	// // Compile the circuit.
	// builder := r1cs.NewBuilder
	// r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// fmt.Println("NbConstraints:", r1cs.GetNbConstraints())

	// // Run the dummy setup.
	// var pk groth16.ProvingKey
	// var vk groth16.VerifyingKey
	// pk, err = groth16.DummySetup(r1cs)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// // Generate the witness.
	// assignment := Circuit{
	// 	X: 0,
	// 	Y: 0,
	// }
	// witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// publicWitness, err := witness.Public()
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// // Generate the proof.
	// proof, err := groth16.Prove(r1cs, pk, witness)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// // Verify the proof.
	// err = groth16.Verify(proof, vk, publicWitness)
	// if err != nil {
	// 	t.Fatal(err)
	// }

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
	assert.CheckCircuit(&circuit, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}
