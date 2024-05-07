package sp1

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/pkg/errors"
	"github.com/succinctlabs/sp1-recursion-gnark/babybear_v2"
)

// Function for serializaton of a gnark groth16 proof to a Solidity-formatted proof.
func SerializeToSolidityRepresentation(proof groth16.Proof, vkeyHash string, commitedValuesDigest string) (SolidityGroth16Proof, error) {
	_proof, ok := proof.(interface{ MarshalSolidity() []byte })
	if !ok {
		panic("proof does not implement MarshalSolidity")
	}
	proofBytes := _proof.MarshalSolidity()

	// solidity contract inputs
	var publicInputs [2]string

	publicInputs[0] = vkeyHash
	publicInputs[1] = commitedValuesDigest

	return SolidityGroth16Proof{
		PublicInputs:  publicInputs,
		SolidityProof: hex.EncodeToString(proofBytes),
	}, nil
}

// Function to serialize a gnark groth16 proof to a Base-64 encoded Groth16Proof.
func SerializeGnarkGroth16Proof(proof *groth16.Proof, witnessInput WitnessInput) Groth16Proof {
	// Serialize the proof to JSON.
	var buf bytes.Buffer
	(*proof).WriteRawTo(&buf)
	proofBytes := buf.Bytes()
	var publicInputs [2]string
	publicInputs[0] = witnessInput.VkeyHash
	publicInputs[1] = witnessInput.CommitedValuesDigest
	encodedProof := hex.EncodeToString(proofBytes)

	return Groth16Proof{
		PublicInputs: publicInputs,
		EncodedProof: encodedProof,
	}
}

// Function to deserialize a hex encoded proof to a groth16.Proof.
func DeserializeSP1Groth16Proof(encodedProof string) (*groth16.Proof, error) {
	decodedBytes, err := hex.DecodeString(encodedProof)
	if err != nil {
		return nil, fmt.Errorf("decoding hex proof: %w", err)
	}

	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(decodedBytes)); err != nil {
		return nil, fmt.Errorf("reading proof from buffer: %w", err)
	}

	return &proof, nil
}

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
	felts := make([]babybear_v2.Variable, len(witnessInput.Felts))
	exts := make([]babybear_v2.ExtensionVariable, len(witnessInput.Exts))
	for i := 0; i < len(witnessInput.Vars); i++ {
		vars[i] = frontend.Variable(witnessInput.Vars[i])
	}
	for i := 0; i < len(witnessInput.Felts); i++ {
		felts[i] = babybear_v2.NewF(witnessInput.Felts[i])
	}
	for i := 0; i < len(witnessInput.Exts); i++ {
		exts[i] = babybear_v2.NewE(witnessInput.Exts[i])
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

// WriteToFile takes a filename and an object that implements io.WriterTo,
// and writes the object's data to the specified file.
func WriteToFile(filename string, writerTo io.WriterTo) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = writerTo.WriteTo(file)
	if err != nil {
		return err
	}

	return nil
}

// Helper function to check if a file exists.
func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return !os.IsNotExist(err)
}

// LoadCircuit checks if the necessary circuit files are in the specified data directory,
// downloads them if not, and loads them into memory.
func LoadCircuit(dataDir, circuitType string) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	r1csPath := filepath.Join(dataDir, "circuit_"+circuitType+".bin")
	pkPath := filepath.Join(dataDir, "pk_"+circuitType+".bin")
	vkPath := filepath.Join(dataDir, "vk_"+circuitType+".bin")

	// Ensure data directory exists
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return nil, nil, nil, errors.Wrap(err, "creating data directory")
		}
	}

	// Check if the R1CS, Proving Key, and Verifying Key files exist in the data directory.
	filesExist := fileExists(r1csPath) && fileExists(pkPath) && fileExists(vkPath)

	if !filesExist {
		return nil, nil, nil, errors.New("circuit files not found")
	} else {
		fmt.Println("Files found, loading circuit...")
	}

	// Load the circuit artifacts into memory
	r1cs, pk, vk, err := LoadCircuitArtifacts(dataDir, circuitType)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "loading circuit artifacts")
	}
	fmt.Println("Circuit artifacts loaded successfully")

	return r1cs, pk, vk, nil
}

// LoadCircuitArtifacts loads the R1CS, Proving Key, and Verifying Key from the specified data directory into memory.
func LoadCircuitArtifacts(dataDir, circuitType string) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	var wg sync.WaitGroup
	var r1cs constraint.ConstraintSystem
	var pk groth16.ProvingKey
	var errR1CS, errPK error

	startTime := time.Now()
	fmt.Printf("Loading artifacts start time %s\n", startTime.Format(time.RFC3339))

	wg.Add(2)
	// Read the R1CS content.
	go func() {
		defer wg.Done()

		r1csFilePath := filepath.Join(dataDir, "circuit_"+circuitType+".bin")
		fmt.Println("Opening R1CS file at:", r1csFilePath)
		r1csFile, err := os.Open(r1csFilePath)
		if err != nil {
			errR1CS = errors.Wrap(err, "opening R1CS file")
			return
		}
		defer r1csFile.Close()

		r1csReader := bufio.NewReader(r1csFile)
		r1csStart := time.Now()
		r1cs = groth16.NewCS(ecc.BN254)
		fmt.Println("Reading R1CS file...")
		if _, err = r1cs.ReadFrom(r1csReader); err != nil {
			errR1CS = errors.Wrap(err, "reading R1CS content from file")
		} else {
			fmt.Printf("R1CS loaded in %s\n", time.Since(r1csStart))
		}
	}()

	// Read the PK content.
	go func() {
		defer wg.Done()

		pkFilePath := filepath.Join(dataDir, "pk_"+circuitType+".bin")
		fmt.Println("Opening PK file at:", pkFilePath)
		pkFile, err := os.Open(pkFilePath)
		if err != nil {
			errPK = errors.Wrap(err, "opening PK file")
			return
		}
		defer pkFile.Close()

		pkReader := bufio.NewReader(pkFile)
		pkStart := time.Now()
		pk = groth16.NewProvingKey(ecc.BN254)
		fmt.Println("Reading PK file...")
		err = pk.ReadDump(pkReader)
		if err != nil {
			errPK = errors.Wrap(err, "reading PK content from file")
		}
		fmt.Printf("PK loaded in %s\n", time.Since(pkStart))
	}()

	wg.Wait()

	if errR1CS != nil {
		return nil, nil, nil, errors.Wrap(errR1CS, "processing R1CS")
	}
	if errPK != nil {
		return nil, nil, nil, errors.Wrap(errPK, "processing PK")
	}

	// Read the VK content
	vkFilePath := filepath.Join(dataDir, "vk_"+circuitType+".bin")
	vkFile, err := os.Open(vkFilePath)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "opening VK file")
	}

	vkFile.Seek(0, io.SeekStart)
	vkContent, err := io.ReadAll(vkFile)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "reading VK content")
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(bytes.NewReader(vkContent))
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "error reading VK content")
	}

	fmt.Printf("Circuit artifacts loaded successfully in %s\n", time.Since(startTime))

	return r1cs, pk, vk, nil

}
