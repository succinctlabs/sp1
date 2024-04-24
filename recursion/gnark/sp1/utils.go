package sp1

import (
	"encoding/json"
	"os"

	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/sp1-recursion-gnark/babybear"
)

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
