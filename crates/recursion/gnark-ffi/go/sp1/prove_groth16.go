//go:build !groth16cuda

package sp1

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

var globalMutex sync.RWMutex
var globalR1cs constraint.ConstraintSystem = groth16.NewCS(ecc.BN254)
var globalR1csInitialized = false
var globalPk groth16.ProvingKey = groth16.NewProvingKey(ecc.BN254)
var globalPkInitialized = false

func ProveGroth16(dataDir string, witnessPath string) Proof {
	// Sanity check the required arguments have been provided.
	if dataDir == "" {
		panic("dataDirStr is required")
	}

	start := time.Now()
	os.Setenv("CONSTRAINTS_JSON", dataDir+"/"+constraintsJsonFile)
	os.Setenv("GROTH16", "1")
	fmt.Printf("Setting environment variables took %s\n", time.Since(start))

	// Read the R1CS.
	globalMutex.Lock()
	if !globalR1csInitialized {
		start = time.Now()
		r1csFile, err := os.Open(dataDir + "/" + groth16CircuitPath)
		if err != nil {
			panic(err)
		}
		r1csReader := bufio.NewReaderSize(r1csFile, 1024*1024)
		globalR1cs.ReadFrom(r1csReader)
		defer r1csFile.Close()
		globalR1csInitialized = true
		fmt.Printf("Reading R1CS took %s\n", time.Since(start))
	}
	globalMutex.Unlock()

	// Read the proving key.
	globalMutex.Lock()
	if !globalPkInitialized {
		start = time.Now()
		pkFile, err := os.Open(dataDir + "/" + groth16PkPath)
		if err != nil {
			panic(err)
		}
		pkReader := bufio.NewReaderSize(pkFile, 1024*1024)
		globalPk.ReadDump(pkReader)
		defer pkFile.Close()
		globalPkInitialized = true
		fmt.Printf("Reading proving key took %s\n", time.Since(start))
	}
	globalMutex.Unlock()

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
	fmt.Printf("Generating witness took %s\n", time.Since(start))

	start = time.Now()
	// Generate the proof.
	proof, err := groth16.Prove(globalR1cs, globalPk, witness)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		panic(err)
	}
	fmt.Printf("Generating proof took %s\n", time.Since(start))

	return NewSP1Groth16Proof(&proof, witnessInput)
}
