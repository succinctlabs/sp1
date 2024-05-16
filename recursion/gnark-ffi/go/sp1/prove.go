package sp1

import (
	"crypto/sha256"
	"encoding/json"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

func ProveGroth16(dataDir string, witnessPath string) Groth16Proof {
	// Sanity check the required arguments have been provided.
	if dataDir == "" {
		panic("dataDirStr is required")
	}
	os.Setenv("CONSTRAINTS_JSON", dataDir+"/"+CONSTRAINTS_JSON_FILE)

	// Read the R1CS.
	r1csFile, err := os.Open(dataDir + "/" + CIRCUIT_PATH)
	if err != nil {
		panic(err)
	}
	r1cs := groth16.NewCS(ecc.BN254)
	r1cs.ReadFrom(r1csFile)

	// Read the proving key.
	pkFile, err := os.Open(dataDir + "/" + PK_PATH)
	if err != nil {
		panic(err)
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	pk.ReadDump(pkFile)

	// Read the verifier key.
	vkFile, err := os.Open(dataDir + "/" + VK_PATH)
	if err != nil {
		panic(err)
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	vk.ReadFrom(vkFile)

	// Read the file.
	data, err := os.ReadFile(witnessPath)
	if err != nil {
		panic(err)
	}

	// Deserialize the JSON data into a slice of Instruction structs
	var witnessInput WitnessInput
	err = json.Unmarshal(data, &witnessInput)
	if err != nil {
		panic(err)
	}

	// Generate the witness.
	assignment := NewCircuit(witnessInput)
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

	return NewSP1Groth16Proof(&proof, witnessInput)
}
