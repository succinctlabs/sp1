package sp1

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
)

func Prove(dataDir string, witnessPath string) Proof {
	// Recover panic if any.
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("panic: ", r)
		}
	}()

	println("proving")
	println("data_dir: ", dataDir)
	println("witness_path: ", witnessPath)
	println("circuit_path: ", circuitPath)
	println("starting proving")

	scsFileOne, err := os.Open(dataDir + "/" + circuitPath)
	if err != nil {
		panic(err)
	}
	// Read all contents of the file into a byte slice
	scsBytes, err := ioutil.ReadAll(scsFileOne)
	if err != nil {
		panic(err)
	}
	println("file length: ", len(scsBytes))
	// Print sha256 hash of the file
	hash := sha256.Sum256(scsBytes)
	fmt.Printf("SHA256 hash of %s: %s\n", circuitPath, hex.EncodeToString(hash[:]))

	scsFileOne.Close()

	// Sanity check the required arguments have been provided.
	if dataDir == "" {
		panic("dataDirStr is required")
	}
	os.Setenv("CONSTRAINTS_JSON", dataDir+"/"+constraintsJsonFile)

	// Reader from bytes
	reader := bytes.NewReader(scsBytes)
	scs := plonk.NewCS(ecc.BN254)
	scs.ReadFrom(reader)

	// Read the proving key.
	pkFile, err := os.Open(dataDir + "/" + pkPath)
	if err != nil {
		panic(err)
	}
	pk := plonk.NewProvingKey(ecc.BN254)
	bufReader := bufio.NewReaderSize(pkFile, 1024*1024)
	pk.UnsafeReadFrom(bufReader)
	defer pkFile.Close()

	// Read the verifier key.
	vkFile, err := os.Open(dataDir + "/" + vkPath)
	if err != nil {
		panic(err)
	}
	vk := plonk.NewVerifyingKey(ecc.BN254)
	vk.ReadFrom(vkFile)
	defer vkFile.Close()

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
	proof, err := plonk.Prove(scs, pk, witness)
	if err != nil {
		panic(err)
	}

	// Verify proof.
	err = plonk.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}

	return NewSP1PlonkBn254Proof(&proof, witnessInput)
}
