package main

/*
#cgo LDFLAGS: ./lib/libbabybear.a -ldl
#include "./lib/babybear.h"
*/
import "C"

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strconv"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/succinctlabs/sp1-recursion-groth16/babybear"
	"github.com/succinctlabs/sp1-recursion-groth16/poseidon2"
)

type Circuit struct {
	Vars                 []frontend.Variable
	Felts                []*babybear.Variable
	Exts                 []*babybear.ExtensionVariable
	VkeyHash             frontend.Variable `gnark:",public"`
	CommitedValuesDigest frontend.Variable `gnark:",public"`
}

type Constraint struct {
	Opcode string     `json:"opcode"`
	Args   [][]string `json:"args"`
}

type Inputs struct {
	Vars                 []string   `json:"vars"`
	Felts                []string   `json:"felts"`
	Exts                 [][]string `json:"exts"`
	VkeyHash             string     `json:"vkey_hash"`
	CommitedValuesDigest string     `json:"commited_values_digest"`
}

type Groth16Proof struct {
	A            [2]string    `json:"a"`
	B            [2][2]string `json:"b"`
	C            [2]string    `json:"c"`
	PublicInputs [2]string    `json:"public_inputs"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	// Get the file name from an environment variable.
	fileName := os.Getenv("CONSTRAINTS_JSON")
	if fileName == "" {
		fileName = "constraints.json"
	}

	// Read the file.
	data, err := os.ReadFile(fileName)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Deserialize the JSON data into a slice of Instruction structs.
	var constraints []Constraint
	err = json.Unmarshal(data, &constraints)
	if err != nil {
		return fmt.Errorf("error deserializing JSON: %v", err)
	}

	hashAPI := poseidon2.NewChip(api)
	fieldAPI := babybear.NewChip(api)
	vars := make(map[string]frontend.Variable)
	felts := make(map[string]*babybear.Variable)
	exts := make(map[string]*babybear.ExtensionVariable)

	// Iterate through the instructions and handle each opcode.
	for _, cs := range constraints {
		switch cs.Opcode {
		case "ImmV":
			vars[cs.Args[0][0]] = frontend.Variable(cs.Args[1][0])
		case "ImmF":
			felts[cs.Args[0][0]] = babybear.NewF(cs.Args[1][0])
		case "ImmE":
			exts[cs.Args[0][0]] = babybear.NewE(cs.Args[1])
		case "AddV":
			vars[cs.Args[0][0]] = api.Add(vars[cs.Args[1][0]], vars[cs.Args[2][0]])
		case "AddF":
			felts[cs.Args[0][0]] = fieldAPI.AddF(felts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "AddE":
			exts[cs.Args[0][0]] = fieldAPI.AddE(exts[cs.Args[1][0]], exts[cs.Args[2][0]])
		case "AddEF":
			exts[cs.Args[0][0]] = fieldAPI.AddEF(exts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "SubV":
			vars[cs.Args[0][0]] = api.Sub(vars[cs.Args[1][0]], vars[cs.Args[2][0]])
		case "SubF":
			felts[cs.Args[0][0]] = fieldAPI.SubF(felts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "SubE":
			exts[cs.Args[0][0]] = fieldAPI.SubE(exts[cs.Args[1][0]], exts[cs.Args[2][0]])
		case "MulV":
			vars[cs.Args[0][0]] = api.Mul(vars[cs.Args[1][0]], vars[cs.Args[2][0]])
		case "MulF":
			felts[cs.Args[0][0]] = fieldAPI.MulF(felts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "MulE":
			exts[cs.Args[0][0]] = fieldAPI.MulE(exts[cs.Args[1][0]], exts[cs.Args[2][0]])
		case "DivE":
			exts[cs.Args[0][0]] = fieldAPI.DivE(exts[cs.Args[1][0]], exts[cs.Args[2][0]])
		case "NegE":
			exts[cs.Args[0][0]] = fieldAPI.NegE(exts[cs.Args[1][0]])
		case "InvE":
			exts[cs.Args[0][0]] = fieldAPI.InvE(exts[cs.Args[1][0]])
		case "Num2BitsV":
			numBits, err := strconv.Atoi(cs.Args[2][0])
			if err != nil {
				return fmt.Errorf("error converting number of bits to int: %v", err)
			}
			bits := api.ToBinary(vars[cs.Args[1][0]], numBits)
			for i := 0; i < len(cs.Args[0]); i++ {
				vars[cs.Args[0][i]] = bits[i]
			}
		case "Num2BitsF":
			bits := fieldAPI.ToBinary(felts[cs.Args[1][0]])
			for i := 0; i < len(cs.Args[0]); i++ {
				vars[cs.Args[0][i]] = bits[i]
			}
		case "Permute":
			state := [3]frontend.Variable{vars[cs.Args[0][0]], vars[cs.Args[1][0]], vars[cs.Args[2][0]]}
			hashAPI.PermuteMut(&state)
			vars[cs.Args[0][0]] = state[0]
			vars[cs.Args[1][0]] = state[1]
			vars[cs.Args[2][0]] = state[2]
		case "SelectV":
			vars[cs.Args[0][0]] = api.Select(vars[cs.Args[1][0]], vars[cs.Args[2][0]], vars[cs.Args[3][0]])
		case "SelectF":
			felts[cs.Args[0][0]] = fieldAPI.SelectF(vars[cs.Args[1][0]], felts[cs.Args[2][0]], felts[cs.Args[3][0]])
		case "SelectE":
			exts[cs.Args[0][0]] = fieldAPI.SelectE(vars[cs.Args[1][0]], exts[cs.Args[2][0]], exts[cs.Args[3][0]])
		case "Ext2Felt":
			out := fieldAPI.Ext2Felt(exts[cs.Args[4][0]])
			for i := 0; i < 4; i++ {
				felts[cs.Args[i][0]] = out[i]
			}
		case "AssertEqV":
			api.AssertIsEqual(vars[cs.Args[0][0]], vars[cs.Args[1][0]])
		case "AssertEqF":
			fieldAPI.AssertIsEqualV(felts[cs.Args[0][0]], felts[cs.Args[1][0]])
		case "AssertEqE":
			fieldAPI.AssertIsEqualE(exts[cs.Args[0][0]], exts[cs.Args[1][0]])
		case "PrintV":
			api.Println(vars[cs.Args[0][0]])
		case "PrintF":
			fieldAPI.PrintF(felts[cs.Args[0][0]])
		case "PrintE":
			fieldAPI.PrintE(exts[cs.Args[0][0]])
		case "WitnessV":
			i, err := strconv.Atoi(cs.Args[1][0])
			if err != nil {
				panic(err)
			}
			vars[cs.Args[0][0]] = circuit.Vars[i]
		case "WitnessF":
			i, err := strconv.Atoi(cs.Args[1][0])
			if err != nil {
				panic(err)
			}
			felts[cs.Args[0][0]] = circuit.Felts[i]
		case "WitnessE":
			i, err := strconv.Atoi(cs.Args[1][0])
			if err != nil {
				panic(err)
			}
			exts[cs.Args[0][0]] = circuit.Exts[i]
		case "CommitVkeyHash":
			element := vars[cs.Args[0][0]]
			api.AssertIsEqual(circuit.VkeyHash, element)
		case "CommitCommitedValuesDigest":
			element := vars[cs.Args[0][0]]
			api.AssertIsEqual(circuit.CommitedValuesDigest, element)
		default:
			return fmt.Errorf("unhandled opcode: %s", cs.Opcode)
		}
	}

	return nil
}

func main() {
	proveCmd := flag.NewFlagSet("prove", flag.ExitOnError)
	dataDirFlag := proveCmd.String("data", "", "Data directory path")
	witnessPathFlag := proveCmd.String("witness", "", "Path to witness")
	proofPathFlag := proveCmd.String("proof", "", "Path to proof")

	buildCmd := flag.NewFlagSet("build", flag.ExitOnError)
	buildDataDirFlag := buildCmd.String("data", "", "Data directory path")

	if len(os.Args) < 2 {
		fmt.Println("expected 'prove' or 'build' subcommand")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "prove":
		proveCmd.Parse(os.Args[2:])
		fmt.Printf("Running 'prove' with data=%s\n", *dataDirFlag)
		buildDir := *dataDirFlag
		witnessPath := *witnessPathFlag
		proofPath := *proofPathFlag
		os.Setenv("CONSTRAINTS_JSON", buildDir+"/constraints.json")

		// Read the R1CS.
		fmt.Println("Reading r1cs...")
		r1csFile, err := os.Open(buildDir + "/r1cs.bin")
		if err != nil {
			panic(err)
		}
		r1cs := groth16.NewCS(ecc.BN254)
		r1cs.ReadFrom(r1csFile)

		// Read the proving key.
		fmt.Println("Reading pk...")
		pkFile, err := os.Open(buildDir + "/pk.bin")
		if err != nil {
			panic(err)
		}
		pk := groth16.NewProvingKey(ecc.BN254)
		pk.ReadFrom(pkFile)

		// Read the verifier key.
		fmt.Println("Reading vk...")
		vkFile, err := os.Open(buildDir + "/vk.bin")
		if err != nil {
			panic(err)
		}
		vk := groth16.NewVerifyingKey(ecc.BN254)
		vk.ReadFrom(vkFile)

		// Generate the witness.
		fmt.Println("Generating witness...")
		data, err := os.ReadFile(witnessPath)
		if err != nil {
			panic(err)
		}

		// Deserialize the JSON data into a slice of Instruction structs
		var inputs Inputs
		err = json.Unmarshal(data, &inputs)
		if err != nil {
			panic(err)
		}

		vars := make([]frontend.Variable, len(inputs.Vars))
		felts := make([]*babybear.Variable, len(inputs.Felts))
		exts := make([]*babybear.ExtensionVariable, len(inputs.Exts))
		for i := 0; i < len(inputs.Vars); i++ {
			vars[i] = frontend.Variable(inputs.Vars[i])
		}
		for i := 0; i < len(inputs.Felts); i++ {
			felts[i] = babybear.NewF(inputs.Felts[i])
		}
		for i := 0; i < len(inputs.Exts); i++ {
			exts[i] = babybear.NewE(inputs.Exts[i])
		}

		// Generate witness.
		fmt.Println("Generating witness...")
		assignment := Circuit{
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
		publicWitness, err := witness.Public()
		if err != nil {
			panic(err)
		}

		// Generate the proof.
		fmt.Println("Generating proof...")
		proof, err := groth16.Prove(r1cs, pk, witness)
		if err != nil {
			panic(err)
		}

		fmt.Println("Verifying proof...")
		err = groth16.Verify(proof, vk, publicWitness)
		if err != nil {
			panic(err)
		}

		// Serialize the proof to JSON.
		const fpSize = 4 * 8
		var buf bytes.Buffer
		proof.WriteRawTo(&buf)
		proofBytes := buf.Bytes()

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
		publicInputs[0] = inputs.VkeyHash
		publicInputs[1] = inputs.CommitedValuesDigest

		groth16Proof := Groth16Proof{
			A:            a,
			B:            b,
			C:            c,
			PublicInputs: publicInputs,
		}

		jsonData, err := json.Marshal(groth16Proof)
		if err != nil {
			panic(err)
		}

		err = os.WriteFile(proofPath, jsonData, 0644)
		if err != nil {
			panic(err)
		}
	case "build":
		buildCmd.Parse(os.Args[2:])
		fmt.Printf("Running 'build' with data=%s\n", *buildDataDirFlag)
		buildDir := *buildDataDirFlag
		os.Setenv("CONSTRAINTS_JSON", buildDir+"/constraints.json")

		// Read the witness.
		data, err := os.ReadFile(buildDir + "/witness.json")
		if err != nil {
			panic(err)
		}

		// Deserialize the JSON data into a slice of Instruction structs
		var witness Inputs
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

		// Initialize the circuit.
		circuit := Circuit{
			Vars:                 vars,
			Felts:                felts,
			Exts:                 exts,
			VkeyHash:             witness.VkeyHash,
			CommitedValuesDigest: witness.CommitedValuesDigest,
		}

		// Compile the circuit.
		builder := r1cs.NewBuilder
		r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
		if err != nil {
			panic(err)
		}

		// Run the dummy setup.
		var pk groth16.ProvingKey
		pk, vk, err := groth16.Setup(r1cs)
		if err != nil {
			panic(err)
		}

		// Create the build directory.
		os.MkdirAll(buildDir, 0755)

		// Write the R1CS.
		r1csFile, err := os.Create(buildDir + "/r1cs.bin")
		if err != nil {
			panic(err)
		}
		r1cs.WriteTo(r1csFile)
		r1csFile.Close()

		// Write the proving key.
		pkFile, err := os.Create(buildDir + "/pk.bin")
		if err != nil {
			panic(err)
		}
		pk.WriteTo(pkFile)
		pkFile.Close()

		// Write the verifier key.
		vkFile, err := os.Create(buildDir + "/vk.bin")
		if err != nil {
			panic(err)
		}
		vk.WriteTo(vkFile)
		vkFile.Close()

		// Write the solidity verifier.
		solidityVerifierFile, err := os.Create(buildDir + "/Groth16Verifier.sol")
		if err != nil {
			panic(err)
		}
		vk.ExportSolidity(solidityVerifierFile)
	default:
		fmt.Println("expected 'prove' or 'build' subcommand")
		os.Exit(1)
	}
}
