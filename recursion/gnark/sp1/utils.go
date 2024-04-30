package sp1

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/sp1-recursion-gnark/babybear"
)

// Function to serialize a gnark groth16 proof to a sp1 groth16 proof.
func SerializeGnarkGroth16Proof(proof *groth16.Proof, witnessInput WitnessInput) (Groth16Proof, error) {
	// Serialize the proof to JSON.
	const fpSize = 4 * 8
	var buf bytes.Buffer
	(*proof).WriteRawTo(&buf)
	proofBytes := buf.Bytes()
	fmt.Println("proofBytes", len(proofBytes))
	fmt.Println("proofBytes", proofBytes)
	var (
		a            [2]string
		b            [2][2]string
		c            [2]string
		publicInputs [2]string
	)
	a[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1]).String()
	a[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2]).String()
	b[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3]).String()
	b[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4]).String()
	b[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5]).String()
	b[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6]).String()
	c[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7]).String()
	c[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8]).String()
	publicInputs[0] = witnessInput.VkeyHash
	publicInputs[1] = witnessInput.CommitedValuesDigest
	encodedProof := base64.StdEncoding.EncodeToString(proofBytes)

	return Groth16Proof{
		A:            a,
		B:            b,
		C:            c,
		PublicInputs: publicInputs,
		EncodedProof: encodedProof,
	}, nil
}

// Function to deserialize SP1.Groth16Proof to Groth16Proof.
func DeserializeSP1Groth16Proof(encodedProof string) (*groth16.Proof, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(encodedProof)
	if err != nil {
		return nil, fmt.Errorf("decoding base64 proof: %w", err)
	}

	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(decodedBytes)); err != nil {
		return nil, fmt.Errorf("reading proof from buffer: %w", err)
	}

	return &proof, nil
}

func LoadEncodedProofFromPath(path string) (Groth16Proof, error) {
	// Read the file.
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}

	// Deserialize the JSON data into a VerifyInput struct
	var input Groth16Proof
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
