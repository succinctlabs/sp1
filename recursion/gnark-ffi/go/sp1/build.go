package sp1

import (
	"crypto/sha256"
	"encoding/json"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func BuildGroth16(dataDir string) {

	// Set the enviroment variable for the constraints file.
	//
	// TODO: There might be some non-determinism if a single processe is running this command
	// multiple times.
	os.Setenv("CONSTRAINTS_JSON", dataDir+"/"+CONSTRAINTS_JSON_FILE)

	// Read the file.
	witnessInputPath := dataDir + "/witness_groth16.json"
	data, err := os.ReadFile(witnessInputPath)
	if err != nil {
		panic(err)
	}

	// Deserialize the JSON data into a slice of Instruction structs
	var witnessInput WitnessInput
	err = json.Unmarshal(data, &witnessInput)
	if err != nil {
		panic(err)
	}

	// Initialize the circuit.
	circuit := NewCircuit(witnessInput)

	// Compile the circuit.
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	// Perform the trusted setup.
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		panic(err)
	}

	// Generate proof.
	assignment := NewCircuit(witnessInput)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(r1cs, pk, witness, backend.WithProverHashToFieldFunction(sha256.New()))
	if err != nil {
		panic(err)
	}

	// Verify proof.
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(proof, vk, publicWitness, backend.WithVerifierHashToFieldFunction(sha256.New()))
	if err != nil {
		panic(err)
	}

	// Create the build directory.
	os.MkdirAll(dataDir, 0755)

	// Write the solidity verifier.
	solidityVerifierFile, err := os.Create(dataDir + "/" + VERIFIER_CONTRACT_PATH)
	if err != nil {
		panic(err)
	}
	vk.ExportSolidity(solidityVerifierFile)

	// Write the R1CS.
	r1csFile, err := os.Create(dataDir + "/" + CIRCUIT_PATH)
	if err != nil {
		panic(err)
	}
	defer r1csFile.Close()
	_, err = r1cs.WriteTo(r1csFile)
	if err != nil {
		panic(err)
	}

	// Write the verifier key.
	vkFile, err := os.Create(dataDir + "/" + VK_PATH)
	if err != nil {
		panic(err)
	}
	defer vkFile.Close()
	_, err = vk.WriteTo(vkFile)
	if err != nil {
		panic(err)
	}

	// Write the proving key.
	pkFile, err := os.Create(dataDir + "/" + PK_PATH)
	if err != nil {
		panic(err)
	}
	defer pkFile.Close()
	pk.WriteDump(pkFile)
}
