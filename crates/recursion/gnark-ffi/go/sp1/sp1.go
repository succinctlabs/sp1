package sp1

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1/babybear"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1/poseidon2"
)

var srsFile string = "srs.bin"
var srsLagrangeFile string = "srs_lagrange.bin"
var constraintsJsonFile string = "constraints.json"
var plonkVerifierContractPath string = "PlonkVerifier.sol"
var groth16VerifierContractPath string = "Groth16Verifier.sol"
var plonkCircuitPath string = "plonk_circuit.bin"
var groth16CircuitPath string = "groth16_circuit.bin"
var plonkVkPath string = "plonk_vk.bin"
var groth16VkPath string = "groth16_vk.bin"
var plonkPkPath string = "plonk_pk.bin"
var groth16PkPath string = "groth16_pk.bin"
var plonkWitnessPath string = "plonk_witness.json"
var groth16WitnessPath string = "groth16_witness.json"

type Circuit struct {
	VkeyHash              frontend.Variable `gnark:",public"`
	CommittedValuesDigest frontend.Variable `gnark:",public"`
	Vars                  []frontend.Variable
	Felts                 []babybear.Variable
	Exts                  []babybear.ExtensionVariable
}

type Constraint struct {
	Opcode string     `json:"opcode"`
	Args   [][]string `json:"args"`
}

type WitnessInput struct {
	Vars                  []string   `json:"vars"`
	Felts                 []string   `json:"felts"`
	Exts                  [][]string `json:"exts"`
	VkeyHash              string     `json:"vkey_hash"`
	CommittedValuesDigest string     `json:"committed_values_digest"`
}

type Proof struct {
	PublicInputs [2]string `json:"public_inputs"`
	EncodedProof string    `json:"encoded_proof"`
	RawProof     string    `json:"raw_proof"`
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
	hashBabyBearAPI := poseidon2.NewBabyBearChip(api)
	fieldAPI := babybear.NewChip(api)
	vars := make(map[string]frontend.Variable)
	felts := make(map[string]babybear.Variable)
	exts := make(map[string]babybear.ExtensionVariable)

	// Iterate through the witnesses and range check them, if necessary.
	for i := 0; i < len(circuit.Felts); i++ {
		if os.Getenv("GROTH16") != "1" {
			fieldAPI.RangeChecker.Check(circuit.Felts[i].Value, 31)
		} else {
			api.ToBinary(circuit.Felts[i].Value, 31)
		}
	}
	for i := 0; i < len(circuit.Exts); i++ {
		for j := 0; j < 4; j++ {
			if os.Getenv("GROTH16") != "1" {
				fieldAPI.RangeChecker.Check(circuit.Exts[i].Value[j].Value, 31)
			} else {
				api.ToBinary(circuit.Exts[i].Value[j].Value, 31)
			}
		}
	}

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
		case "DivF":
			felts[cs.Args[0][0]] = fieldAPI.DivF(felts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "SubE":
			exts[cs.Args[0][0]] = fieldAPI.SubE(exts[cs.Args[1][0]], exts[cs.Args[2][0]])
		case "SubEF":
			exts[cs.Args[0][0]] = fieldAPI.SubEF(exts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "MulV":
			vars[cs.Args[0][0]] = api.Mul(vars[cs.Args[1][0]], vars[cs.Args[2][0]])
		case "MulF":
			felts[cs.Args[0][0]] = fieldAPI.MulF(felts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "MulE":
			exts[cs.Args[0][0]] = fieldAPI.MulE(exts[cs.Args[1][0]], exts[cs.Args[2][0]])
		case "MulEF":
			exts[cs.Args[0][0]] = fieldAPI.MulEF(exts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "DivE":
			exts[cs.Args[0][0]] = fieldAPI.DivE(exts[cs.Args[1][0]], exts[cs.Args[2][0]])
		case "DivEF":
			exts[cs.Args[0][0]] = fieldAPI.DivEF(exts[cs.Args[1][0]], felts[cs.Args[2][0]])
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
		case "PermuteBabyBear":
			var state [16]babybear.Variable
			for i := 0; i < 16; i++ {
				state[i] = felts[cs.Args[i][0]]
			}
			hashBabyBearAPI.PermuteMut(&state)
			for i := 0; i < 16; i++ {
				felts[cs.Args[i][0]] = state[i]
			}
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
			fieldAPI.AssertIsEqualF(felts[cs.Args[0][0]], felts[cs.Args[1][0]])
		case "AssertNeF":
			fieldAPI.AssertNotEqualF(felts[cs.Args[0][0]], felts[cs.Args[1][0]])
		case "AssertEqE":
			fieldAPI.AssertIsEqualE(exts[cs.Args[0][0]], exts[cs.Args[1][0]])
		case "PrintV":
			api.Println(vars[cs.Args[0][0]])
		case "PrintF":
			f := fieldAPI.ReduceSlow(felts[cs.Args[0][0]])
			api.Println(f.Value)
		case "PrintE":
			e := fieldAPI.ReduceE(exts[cs.Args[0][0]])
			api.Println(e.Value[0].Value)
			api.Println(e.Value[1].Value)
			api.Println(e.Value[2].Value)
			api.Println(e.Value[3].Value)
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
			api.AssertIsEqual(circuit.CommittedValuesDigest, element)
		case "CircuitFelts2Ext":
			exts[cs.Args[0][0]] = babybear.Felts2Ext(felts[cs.Args[1][0]], felts[cs.Args[2][0]], felts[cs.Args[3][0]], felts[cs.Args[4][0]])
		case "CircuitFelt2Var":
			vars[cs.Args[0][0]] = fieldAPI.ReduceSlow(felts[cs.Args[1][0]]).Value
		case "ReduceE":
			exts[cs.Args[0][0]] = fieldAPI.ReduceE(exts[cs.Args[0][0]])
		default:
			return fmt.Errorf("unhandled opcode: %s", cs.Opcode)
		}
	}

	return nil
}
