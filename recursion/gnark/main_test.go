package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/succinctlabs/sp1-recursion-gnark/babybear_v2"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1"
)

func TestMain(t *testing.T) {
	assert := test.NewAssert(t)

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

	assert.CheckCircuit(&circuit, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))

	// // Compile the circuit.
	// builder := r1cs.NewBuilder
	// r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Println("NbConstraints:", r1cs.GetNbConstraints())

	// // Run the dummy setup.
	// var pk groth16.ProvingKey
	// pk, err = groth16.DummySetup(r1cs)
	// if err != nil {
	// 	panic(err)
	// }

	// // Generate witness.
	// vars = make([]frontend.Variable, len(inputs.Vars))
	// felts = make([]babybear_v2.Variable, len(inputs.Felts))
	// exts = make([]babybear_v2.ExtensionVariable, len(inputs.Exts))
	// for i := 0; i < len(inputs.Vars); i++ {
	// 	vars[i] = frontend.Variable(inputs.Vars[i])
	// }
	// for i := 0; i < len(inputs.Felts); i++ {
	// 	felts[i] = babybear_v2.NewF(inputs.Felts[i])
	// }
	// for i := 0; i < len(inputs.Exts); i++ {
	// 	exts[i] = babybear_v2.NewE(inputs.Exts[i])
	// }
	// assignment := sp1.Circuit{
	// 	Vars:                 vars,
	// 	Felts:                felts,
	// 	Exts:                 exts,
	// 	VkeyHash:             inputs.VkeyHash,
	// 	CommitedValuesDigest: inputs.CommitedValuesDigest,
	// }
	// witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	// if err != nil {
	// 	panic(err)
	// }

	// // Generate the proof.
	// _, err = groth16.Prove(r1cs, pk, witness)
	// if err != nil {
	// 	panic(err)
	// }

	// This was the old way we were testing the circuit, but it seems to have edge cases where it
	// doesn't properly check that the prover will succeed.
	//
	// assert.CheckCircuit(&circuit, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}

type MyCircuit struct {
	X            frontend.Variable `gnark:",public"`
	Y            frontend.Variable `gnark:",public"`
	Z            frontend.Variable `gnark:",public"`
	DoRangeCheck bool
}

func (circuit *MyCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(circuit.Z, api.Add(circuit.X, circuit.Y))
	if true || circuit.DoRangeCheck {
		rangeChecker := rangecheck.New(api)
		rangeChecker.Check(circuit.X, 8)
	}
	return nil
}

type Groth16ProofData struct {
	Proof  []string `json:"proof"`
	Inputs []string `json:"inputs"`
}

func TestGroth16(t *testing.T) {
	fmt.Println("Testing Groth16")

	circuit := MyCircuit{DoRangeCheck: false}

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		panic(err)
	}

	buf := new(bytes.Buffer)
	err = vk.ExportSolidity(buf)
	if err != nil {
		panic(err)
	}
	content := buf.String()

	contractFile, err := os.Create("VerifierGroth16.sol")
	if err != nil {
		panic(err)
	}
	w := bufio.NewWriter(contractFile)
	// write the new content to the writer
	_, err = w.Write([]byte(content))
	if err != nil {
		panic(err)
	}
	contractFile.Close()

	assignment := MyCircuit{
		X: 1,
		Y: 2,
		Z: 3,
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	proof, _ := groth16.Prove(r1cs, pk, witness)

	const fpSize = 4 * 8
	buf = new(bytes.Buffer)
	proof.WriteRawTo(buf)
	proofBytes := buf.Bytes()

	proofs := make([]string, 8)
	// Print out the proof
	for i := 0; i < 8; i++ {
		proofs[i] = "0x" + hex.EncodeToString(proofBytes[i*fpSize:(i+1)*fpSize])
	}

	publicWitness, _ := witness.Public()
	publicWitnessBytes, _ := publicWitness.MarshalBinary()
	publicWitnessBytes = publicWitnessBytes[12:] // We cut off the first 12 bytes because they encode length information

	commitmentCountBigInt := new(big.Int).SetBytes(proofBytes[fpSize*8 : fpSize*8+4])
	commitmentCount := int(commitmentCountBigInt.Int64())

	var commitments []*big.Int = make([]*big.Int, 2*commitmentCount)
	var commitmentPok [2]*big.Int

	for i := 0; i < 2*commitmentCount; i++ {
		commitments[i] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+i*fpSize : fpSize*8+4+(i+1)*fpSize])
	}

	commitmentPok[0] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize : fpSize*8+4+2*commitmentCount*fpSize+fpSize])
	commitmentPok[1] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize+fpSize : fpSize*8+4+2*commitmentCount*fpSize+2*fpSize])

	fmt.Println("uint256[8] memory proofs = [")
	for i := 0; i < 8; i++ {
		fmt.Print(proofs[i])
		if i != 7 {
			fmt.Println(",")
		}
	}
	fmt.Println("];")

	fmt.Println("uint256[2] memory commitments = [")
	for i := 0; i < 2*commitmentCount; i++ {
		fmt.Print(commitments[i])
		if i != 2*commitmentCount-1 {
			fmt.Println(",")
		}
	}
	fmt.Println("];")

	fmt.Println("uint256[2] memory commitmentPok = [")
	for i := 0; i < 2; i++ {
		fmt.Print(commitmentPok[i])
		if i != 1 {
			fmt.Println(",")
		}
	}
	fmt.Println("];")

	fmt.Println("uint256[3] memory inputs = [")
	fmt.Println("uint256(1),")
	fmt.Println("uint256(2),")
	fmt.Println("uint256(3)")
	fmt.Println("];")

	inputs := make([]string, 3)
	for i := 0; i < 3; i++ {
		inputs[i] = "0x" + hex.EncodeToString(publicWitnessBytes[i*fpSize:(i+1)*fpSize])
	}

	// Create the data struct and populate it
	data := Groth16ProofData{
		Proof:  proofs,
		Inputs: inputs,
	}

	// Marshal the data into JSON
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling to JSON:", err)
		return
	}

	// Write the JSON to a file
	err = ioutil.WriteFile("groth16_proof_data.json", jsonData, 0644)
	if err != nil {
		fmt.Println("Error writing to file:", err)
	}
}

func TestPlonk(t *testing.T) {
	fmt.Println("Testing Groth16")

	circuit := MyCircuit{DoRangeCheck: false}

	scs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	// Sourced from: https://github.com/Consensys/gnark/blob/88712e5ce5dbbb6a1efca23b659f967d36261de4/examples/plonk/main.go#L86-L89
	srs, srsLagrange, err := unsafekzg.NewSRS(scs)
	if err != nil {
		panic(err)
	}

	pk, vk, err := plonk.Setup(scs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}

	buf := new(bytes.Buffer)
	err = vk.ExportSolidity(buf)
	if err != nil {
		panic(err)
	}
	content := buf.String()

	contractFile, err := os.Create("VerifierPlonk.sol")
	if err != nil {
		panic(err)
	}
	w := bufio.NewWriter(contractFile)
	// write the new content to the writer
	_, err = w.Write([]byte(content))
	if err != nil {
		panic(err)
	}
	contractFile.Close()

	assignment := MyCircuit{
		X: 1,
		Y: 2,
		Z: 3,
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	proof, _ := plonk.Prove(scs, pk, witness)

	_proof := proof.(*plonk_bn254.Proof)
	proofStr := hex.EncodeToString(_proof.MarshalSolidity())
	fmt.Println(proofStr)
}
