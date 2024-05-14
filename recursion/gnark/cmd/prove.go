package cmd

import (
	"crypto/sha256"
	"encoding/json"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/spf13/cobra"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1"
)

var proveCmdDataDir string
var proveCmdWitnessPath string
var proveCmdProofPath string

func init() {
	proveCmd.Flags().StringVar(&proveCmdDataDir, "data", "", "")
	proveCmd.Flags().StringVar(&proveCmdWitnessPath, "witness", "", "")
	proveCmd.Flags().StringVar(&proveCmdProofPath, "proof", "", "")
}

var proveCmd = &cobra.Command{
	Use: "prove",
	Run: func(cmd *cobra.Command, args []string) {
		// Sanity check the required arguments have been provided.
		if proveCmdDataDir == "" {
			panic("--data is required")
		}
		os.Setenv("CONSTRAINTS_JSON", buildCmdDataDir+"/"+CONSTRAINTS_JSON_FILE)

		// Read the R1CS.
		r1csFile, err := os.Open(proveCmdDataDir + "/" + CIRCUIT_PATH)
		if err != nil {
			panic(err)
		}
		r1cs := groth16.NewCS(ecc.BN254)
		r1cs.ReadFrom(r1csFile)

		// Read the proving key.
		pkFile, err := os.Open(proveCmdDataDir + "/" + PK_PATH)
		if err != nil {
			panic(err)
		}
		pk := groth16.NewProvingKey(ecc.BN254)
		pk.ReadDump(pkFile)

		// Read the verifier key.
		vkFile, err := os.Open(proveCmdDataDir + "/" + VK_PATH)
		if err != nil {
			panic(err)
		}
		vk := groth16.NewVerifyingKey(ecc.BN254)
		vk.ReadFrom(vkFile)

		// Read the file.
		data, err := os.ReadFile(proveCmdDataDir + "/" + WITNESS_JSON_FILE)
		if err != nil {
			panic(err)
		}

		// Deserialize the JSON data into a slice of Instruction structs
		var witnessInput sp1.WitnessInput
		err = json.Unmarshal(data, &witnessInput)
		if err != nil {
			panic(err)
		}

		// Generate the witness.
		assignment := sp1.NewCircuit(witnessInput)
		witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
		if err != nil {
			panic(err)
		}
		publicWitness, err := witness.Public()
		if err != nil {
			panic(err)
		}

		// Generate the proof.
		proof, err := groth16.Prove(r1cs, pk, witness, backend.WithProverHashToFieldFunction(sha256.New()))
		if err != nil {
			panic(err)
		}

		// Verify proof.
		err = groth16.Verify(proof, vk, publicWitness, backend.WithVerifierHashToFieldFunction(sha256.New()))
		if err != nil {
			panic(err)
		}

		// Serialize the proof to a file.
		sp1Groth16Proof := sp1.NewSP1Groth16Proof(&proof, witnessInput)
		jsonData, err := json.Marshal(sp1Groth16Proof)
		if err != nil {
			panic(err)
		}
		err = os.WriteFile(proveCmdProofPath, jsonData, 0644)
		if err != nil {
			panic(err)
		}
	},
}
