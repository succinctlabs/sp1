package main

/*
#include "./babybear.h"

typedef struct {
	char *PublicInputs[2];
	char *EncodedProof;
	char *RawProof;
} C_Groth16Proof;
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1"
)

func main() {}

//export ProveGroth16
func ProveGroth16(dataDir *C.char, witnessPath *C.char) *C.C_Groth16Proof {
	dataDirString := C.GoString(dataDir)
	witnessPathString := C.GoString(witnessPath)

	sp1Groth16Proof := sp1.ProveGroth16(dataDirString, witnessPathString)

	ms := C.malloc(C.sizeof_C_Groth16Proof)
	if ms == nil {
		return nil
	}

	structPtr := (*C.C_Groth16Proof)(ms)
	structPtr.PublicInputs[0] = C.CString(sp1Groth16Proof.PublicInputs[0])
	structPtr.PublicInputs[1] = C.CString(sp1Groth16Proof.PublicInputs[1])
	structPtr.EncodedProof = C.CString(sp1Groth16Proof.EncodedProof)
	structPtr.RawProof = C.CString(sp1Groth16Proof.RawProof)
	return structPtr
}

//export BuildGroth16
func BuildGroth16(dataDir *C.char) {
	// Sanity check the required arguments have been provided.
	dataDirString := C.GoString(dataDir)

	sp1.BuildGroth16(dataDirString)
}

//export VerifyGroth16
func VerifyGroth16(dataDir *C.char, proof *C.char, vkeyHash *C.char, commitedValuesDigest *C.char) *C.char {
	dataDirString := C.GoString(dataDir)
	proofString := C.GoString(proof)
	vkeyHashString := C.GoString(vkeyHash)
	commitedValuesDigestString := C.GoString(commitedValuesDigest)

	err := sp1.VerifyGroth16(dataDirString, proofString, vkeyHashString, commitedValuesDigestString)
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

var testMutex = &sync.Mutex{}

//export TestGroth16
func TestGroth16(witnessPath *C.char, constraintsJson *C.char) *C.char {
	// Because of the global env variables used here, we need to lock this function
	testMutex.Lock()
	witnessPathString := C.GoString(witnessPath)
	constraintsJsonString := C.GoString(constraintsJson)
	os.Setenv("WITNESS_JSON", witnessPathString)
	os.Setenv("CONSTRAINTS_JSON", constraintsJsonString)
	err := TestMain()
	testMutex.Unlock()
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

func TestMain() error {
	// Get the file name from an environment variable.
	fileName := os.Getenv("WITNESS_JSON")
	if fileName == "" {
		fileName = "witness.json"
	}

	// Read the file.
	data, err := os.ReadFile(fileName)
	if err != nil {
		return err
	}

	// Deserialize the JSON data into a slice of Instruction structs
	var inputs sp1.WitnessInput
	err = json.Unmarshal(data, &inputs)
	if err != nil {
		return err
	}

	// Compile the circuit.
	circuit := sp1.NewCircuit(inputs)
	builder := r1cs.NewBuilder
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	if err != nil {
		return err
	}
	fmt.Println("[sp1] groth16 verifier constraints:", r1cs.GetNbConstraints())

	// Run the dummy setup.
	var pk groth16.ProvingKey
	pk, err = groth16.DummySetup(r1cs)
	if err != nil {
		return err
	}

	// Generate witness.
	assignment := sp1.NewCircuit(inputs)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}

	// Generate the proof.
	_, err = groth16.Prove(r1cs, pk, witness)
	if err != nil {
		return err
	}

	return nil
}
