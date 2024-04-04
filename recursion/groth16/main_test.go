package main

import (
	"testing"

	"github.com/consensys/gnark/test"
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

	// Run some sanity checks.
	assert.CheckCircuit(&Circuit{
		X: 0,
		Y: 0,
	})

	// assert.ProverSucceeded(&circuit, &Circuit{
	// 	X: 0,
	// 	Y: 0,
	// }, test.WithCurves(ecc.BN254))
}
