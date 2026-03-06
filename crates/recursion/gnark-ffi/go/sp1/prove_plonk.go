package sp1

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

// Global cache for the constraint system, proving key, and verifying key,
// similar to prove_groth16.go.
var globalPlonkMutex sync.RWMutex
var globalPlonkScs constraint.ConstraintSystem = plonk.NewCS(ecc.BN254)
var globalPlonkScsInitialized = false
var globalPlonkPk plonk.ProvingKey = plonk.NewProvingKey(ecc.BN254)
var globalPlonkPkInitialized = false
var globalPlonkVk plonk.VerifyingKey = plonk.NewVerifyingKey(ecc.BN254)
var globalPlonkVkInitialized = false

func ProvePlonk(dataDir string, witnessPath string) Proof {
	// Sanity check the required arguments have been provided.
	if dataDir == "" {
		panic("dataDirStr is required")
	}

	start := time.Now()
	os.Setenv("CONSTRAINTS_JSON", dataDir+"/"+constraintsJsonFile)
	fmt.Printf("Setting environment variables took %s\n", time.Since(start))

	// Read the R1CS (cached globally after first call). `dataDir` is the path
	// to the circuit artifacts directory and does not change during the lifetime
	// of this server, so it is safe to cache these.
	globalPlonkMutex.Lock()
	if !globalPlonkScsInitialized {
		start = time.Now()
		scsFile, err := os.Open(dataDir + "/" + plonkCircuitPath)
		if err != nil {
			panic(err)
		}
		scsReader := bufio.NewReaderSize(scsFile, 1024*1024)
		globalPlonkScs.ReadFrom(scsReader)
		defer scsFile.Close()
		globalPlonkScsInitialized = true
		fmt.Printf("Reading R1CS took %s\n", time.Since(start))
	}
	globalPlonkMutex.Unlock()

	// Read the proving key.
	globalPlonkMutex.Lock()
	if !globalPlonkPkInitialized {
		start = time.Now()
		pkFile, err := os.Open(dataDir + "/" + plonkPkPath)
		if err != nil {
			panic(err)
		}
		pkReader := bufio.NewReaderSize(pkFile, 1024*1024)
		globalPlonkPk.UnsafeReadFrom(pkReader)
		defer pkFile.Close()
		globalPlonkPkInitialized = true
		fmt.Printf("Reading proving key took %s\n", time.Since(start))
	}
	globalPlonkMutex.Unlock()

	// Read the verifier key.
	globalPlonkMutex.Lock()
	if !globalPlonkVkInitialized {
		start = time.Now()
		vkFile, err := os.Open(dataDir + "/" + plonkVkPath)
		if err != nil {
			panic(err)
		}
		globalPlonkVk.ReadFrom(vkFile)
		defer vkFile.Close()
		globalPlonkVkInitialized = true
		fmt.Printf("Reading verifying key took %s\n", time.Since(start))
	}
	globalPlonkMutex.Unlock()

	start = time.Now()
	// Read the file.
	data, err := os.ReadFile(witnessPath)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Reading witness file took %s\n", time.Since(start))

	start = time.Now()
	// Deserialize the JSON data into a slice of Instruction structs
	var witnessInput WitnessInput
	err = json.Unmarshal(data, &witnessInput)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Deserializing JSON data took %s\n", time.Since(start))

	start = time.Now()
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
	fmt.Printf("Generating witness took %s\n", time.Since(start))

	start = time.Now()
	// Generate the proof.
	proof, err := plonk.Prove(globalPlonkScs, globalPlonkPk, witness)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		panic(err)
	}
	fmt.Printf("Generating proof took %s\n", time.Since(start))

	start = time.Now()
	// Verify proof.
	err = plonk.Verify(proof, globalPlonkVk, publicWitness)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Verifying proof took %s\n", time.Since(start))

	return NewSP1PlonkBn254Proof(&proof, witnessInput)
}
