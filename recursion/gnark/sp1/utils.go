package sp1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/sp1-recursion-gnark/babybear"
)

// Function to deserialize SP1.Groth16Proof to Groth16Proof.
func DeserializeSP1Groth16Proof(sp1Proof Groth16Proof) (*groth16.Proof, error) {
	const fpSize = 4 * 8
	const bufSize = 388
	proofBytes := make([]byte, bufSize)
	for i, val := range []string{sp1Proof.A[0], sp1Proof.A[1], sp1Proof.B[0][0], sp1Proof.B[0][1], sp1Proof.B[1][0], sp1Proof.B[1][1], sp1Proof.C[0], sp1Proof.C[1]} {
		bigInt, ok := new(big.Int).SetString(val, 10)
		if !ok {
			return nil, fmt.Errorf("invalid big.Int value: %s", val)
		}
		fmt.Println("bigInt length", len(bigInt.Bytes()))
		copy(proofBytes[fpSize*i:fpSize*(i+1)], bigInt.Bytes())
	}

	var buf bytes.Buffer
	buf.Write(proofBytes)
	proof := groth16.NewProof(ecc.BN254)

	if _, err := proof.ReadFrom(&buf); err != nil {
		return nil, fmt.Errorf("reading proof from buffer: %w", err)
	}

	return &proof, nil
}

func LoadVerifyInputFromPath(path string) (VerifyInput, error) {
	// Read the file.
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}

	// Deserialize the JSON data into a VerifyInput struct
	var input VerifyInput
	err = json.Unmarshal(data, &input)
	if err != nil {
		panic(err)
	}

	return input, nil
}

func LoadWitnessInputFromPath(path string) (WitnessInput, error) {
	// Read the file.
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}

	// Deserialize the JSON data into a slice of Instruction structs
	var inputs WitnessInput
	err = json.Unmarshal(data, &inputs)
	if err != nil {
		panic(err)
	}

	return inputs, nil
}

func NewCircuitFromWitness(witnessInput WitnessInput) Circuit {
	// Load the vars, felts, and exts from the witness input.
	vars := make([]frontend.Variable, len(witnessInput.Vars))
	felts := make([]*babybear.Variable, len(witnessInput.Felts))
	exts := make([]*babybear.ExtensionVariable, len(witnessInput.Exts))
	for i := 0; i < len(witnessInput.Vars); i++ {
		vars[i] = frontend.Variable(witnessInput.Vars[i])
	}
	for i := 0; i < len(witnessInput.Felts); i++ {
		felts[i] = babybear.NewF(witnessInput.Felts[i])
	}
	for i := 0; i < len(witnessInput.Exts); i++ {
		exts[i] = babybear.NewE(witnessInput.Exts[i])
	}

	// Initialize the circuit.
	return Circuit{
		Vars:                 vars,
		Felts:                felts,
		Exts:                 exts,
		VkeyHash:             witnessInput.VkeyHash,
		CommitedValuesDigest: witnessInput.CommitedValuesDigest,
	}
}
