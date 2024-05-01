package sp1

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

// Build a gnark plonk circuit and write the R1CS, the proving key and the verifier key to a file.
func BuildPlonkBn254(buildDir string) error {
	// Load the witness input.
	witnessInput, err := LoadWitnessInputFromPath(buildDir + "/witness_plonk_bn254.json")
	if err != nil {
		return err
	}

	// Initialize the circuit.
	circuit := NewCircuitFromWitness(witnessInput)

	// Compile the circuit.
	builder := scs.NewBuilder
	scs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	if err != nil {
		return err
	}

	// Sourced from: https://github.com/Consensys/gnark/blob/88712e5ce5dbbb6a1efca23b659f967d36261de4/examples/plonk/main.go#L86-L89
	srs, srsLagrange, err := unsafekzg.NewSRS(scs)
	if err != nil {
		return err
	}

	pk, vk, err := plonk.Setup(scs, srs, srsLagrange)
	if err != nil {
		return err
	}

	// Create the build directory.
	os.MkdirAll(buildDir, 0755)

	// Write the R1CS.
	WriteToFile(buildDir+"/circuit_plonk_bn254.bin", scs)

	// Write the proving key.
	WriteToFile(buildDir+"/pk_plonk_bn254.bin", pk)

	// Write the verifier key.
	WriteToFile(buildDir+"/vk_plonk_bn254.bin", vk)

	// Write the solidity verifier.
	solidityVerifierFile, err := os.Create(buildDir + "/PlonkBn254Verifier.sol")
	if err != nil {
		return err
	}
	vk.ExportSolidity(solidityVerifierFile)
	return nil
}

// Generate a gnark plonk proof for a given witness and write the proof to a file. Reads the
// R1CS, the proving key and the verifier key from the build directory.
func ProvePlonkBn254(buildDir string, witnessPath string, proofPath string) error {
	// Read the R1CS.
	fmt.Println("Reading scs...")
	scsFile, err := os.Open(buildDir + "/circuit_plonk_bn254.bin")
	if err != nil {
		return err
	}
	scs := plonk.NewCS(ecc.BN254)
	scs.ReadFrom(scsFile)

	// Read the proving key.
	fmt.Println("Reading pk...")
	pkFile, err := os.Open(buildDir + "/pk_plonk_bn254.bin")
	if err != nil {
		return err
	}
	pk := plonk.NewProvingKey(ecc.BN254)
	pk.ReadFrom(pkFile)

	// Read the verifier key.
	fmt.Println("Reading vk...")
	vkFile, err := os.Open(buildDir + "/vk_plonk_bn254.bin")
	if err != nil {
		return err
	}
	vk := plonk.NewVerifyingKey(ecc.BN254)
	vk.ReadFrom(vkFile)

	// Generate the witness.
	witnessInput, err := LoadWitnessInputFromPath(witnessPath)
	if err != nil {
		return err
	}
	assignment := NewCircuitFromWitness(witnessInput)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}

	// Generate the proof.
	fmt.Println("Generating proof...")
	proof, err := plonk.Prove(scs, pk, witness)
	if err != nil {
		return err
	}

	plonkBn254ProofRaw := proof.(*plonk_bn254.Proof)
	plonkBn254Proof := PlonkBn254Proof{
		Proof: "0x" + hex.EncodeToString(plonkBn254ProofRaw.MarshalSolidity()),
		PublicInputs: [2]string{
			witnessInput.VkeyHash,
			witnessInput.CommitedValuesDigest,
		},
	}

	jsonData, err := json.Marshal(plonkBn254Proof)
	if err != nil {
		return err
	}

	err = os.WriteFile(proofPath, jsonData, 0644)
	if err != nil {
		return err
	}
	return nil
}
