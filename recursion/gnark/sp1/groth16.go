package sp1

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Build a gnark groth16 circuit and write the resulting build files to the build directory. This
// includes the R1CS, the proving key, the verifier key, and the solidity verifier.
func BuildGroth16(buildDir string) error {
	// Load the witness input.
	witnessInput, err := LoadWitnessInputFromPath(buildDir + "/witness_groth16.json")
	if err != nil {
		panic(err)
	}

	// Initialize the circuit.
	circuit := NewCircuitFromWitness(witnessInput)

	// Compile the circuit.
	// p := profile.Start(profile.WithPath("sp1.pprof"))
	builder := r1cs.NewBuilder
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	if err != nil {
		panic(err)
	}
	// p.Stop()
	fmt.Println("NbConstraints:", r1cs.GetNbConstraints())

	// Run the trusted setup.
	var pk groth16.ProvingKey
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		panic(err)
	}

	// Create the build directory.
	os.MkdirAll(buildDir, 0755)

	// Write the R1CS.
	WriteToFile(buildDir+"/circuit_groth16.bin", r1cs)

	// Write the verifier key.
	WriteToFile(buildDir+"/vk_groth16.bin", vk)

	// Write the proving key.
	pkFile, err := os.Create(buildDir + "/pk_groth16.bin")
	if err != nil {
		return err
	}
	defer pkFile.Close()
	pk.WriteDump(pkFile)

	// Write the solidity verifier.
	solidityVerifierFile, err := os.Create(buildDir + "/Groth16Verifier.sol")
	if err != nil {
		return err
	}
	vk.ExportSolidity(solidityVerifierFile)
	return nil
}

// Generate a gnark groth16 proof for a given witness and write the proof to a file. Reads the
// R1CS, the proving key and the verifier key from the build directory.
func ProveGroth16(buildDir string, witnessPath string, proofPath string) error {
	// Read the R1CS.
	fmt.Println("Reading r1cs...")
	r1csFile, err := os.Open(buildDir + "/circuit_groth16.bin")
	if err != nil {
		return err
	}
	r1cs := groth16.NewCS(ecc.BN254)
	r1cs.ReadFrom(r1csFile)

	// Read the proving key.
	fmt.Println("Reading pk...")
	pkFile, err := os.Open(buildDir + "/pk_groth16.bin")
	if err != nil {
		return err
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	pk.ReadDump(pkFile)

	// Read the verifier key.
	fmt.Println("Reading vk...")
	vkFile, err := os.Open(buildDir + "/vk_groth16.bin")
	if err != nil {
		return err
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
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
	publicWitness, err := witness.Public()
	if err != nil {
		return err
	}

	// Generate the proof.
	fmt.Println("Generating proof...")
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		return err
	}

	fmt.Println("Verifying proof...")
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		return err
	}

	// Serialize the proof to JSON.
	groth16Proof, err := SerializeGnarkGroth16Proof(&proof, witnessInput)
	if err != nil {
		return err
	}

	jsonData, err := json.Marshal(groth16Proof)
	if err != nil {
		return err
	}

	err = os.WriteFile(proofPath, jsonData, 0644)
	if err != nil {
		return err
	}
	return nil
}

// Verify a hex-encoded gnark groth16 proof serialized from gnark.
// 1. Deserialize the verifier key.
// 2. Deserialize the proof.
// 3. Construct the public witness from the verify input.
// 4. Verify the proof.
func VerifyGroth16(buildDir string, hexEncodedProof string, vkeyHash string, commitedValuesDigest string) error {
	// Read the verifier key.
	fmt.Println("Reading vk...")
	fmt.Println(buildDir + "/vk_groth16.bin")
	vkFile, err := os.Open(buildDir + "/vk_groth16.bin")
	if err != nil {
		return err
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	vk.ReadFrom(vkFile)

	// Encoded proof to gnark groth16 proof.
	proof, err := DeserializeSP1Groth16Proof(hexEncodedProof)
	if err != nil {
		return err
	}

	// Construct the public witness from the verify input.
	assignment := Circuit{
		VkeyHash:             vkeyHash,
		CommitedValuesDigest: commitedValuesDigest,
	}
	publicWitness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}

	// Verify the proof.
	err = groth16.Verify(*proof, vk, publicWitness)
	if err != nil {
		return err
	}

	return nil
}

// Convert a hex-encoded gnark groth16 proof to a Solidity-formatted groth16 proof.
func ConvertGroth16(dataDir string, hexEncodedProof string, vkeyHash string, commitedValuesDigest string) error {
	// Encoded proof to gnark groth16 proof.
	proof, err := DeserializeSP1Groth16Proof(hexEncodedProof)
	if err != nil {
		return err
	}

	// Serialize to solidity representation.
	solidityProof, err := SerializeToSolidityRepresentation(*proof, vkeyHash, commitedValuesDigest)
	if err != nil {
		return err
	}

	// Serialize to json.
	jsonData, err := json.Marshal(solidityProof)
	if err != nil {
		return err
	}

	proofPath := dataDir + "/solidity_proof.json"

	// Write the Solidity-formatted proof to solidity_proof.json.
	err = os.WriteFile(proofPath, jsonData, 0644)
	if err != nil {
		return err
	}
	return nil
}
