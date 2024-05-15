package main

/*
#include "./lib/babybear.h"

typedef struct {
	char *PublicInputs[2];
	char *EncodedProof;
	char *RawProof;
} C_Groth16Proof;

*/
import "C"
import (
	"crypto/sha256"
	"encoding/json"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1"
)

func main() {
}

//export Test
func Test(ptr *C.char) {
	str := C.GoString(ptr)
	println(str)
}

//export Test2
func Test2() {
	println("test2")
}

//export Test3
func Test3(a uint32) uint32 {
	cuint := C.uint32_t(a)
	result := C.babybearextinv(cuint, cuint, cuint, cuint, cuint)
	return uint32(result)
}

var CONSTRAINTS_JSON_FILE string = "constraints_groth16.json"
var WITNESS_JSON_FILE string = "witness_groth16.json"
var VERIFIER_CONTRACT_PATH string = "SP1Verifier.sol"
var CIRCUIT_PATH string = "circuit_groth16.bin"
var VK_PATH string = "vk_groth16.bin"
var PK_PATH string = "pk_groth16.bin"

var CircuitDataMap = make(map[uint32]groth16.ProvingKey)

//export ProveGroth16
func ProveGroth16(dataDir *C.char, witnessPath *C.char) *C.C_Groth16Proof {
	dataDirStr := C.GoString(dataDir)
	witnessPathStr := C.GoString(witnessPath)

	// Sanity check the required arguments have been provided.
	if dataDirStr == "" {
		panic("dataDirStr is required")
	}
	os.Setenv("CONSTRAINTS_JSON", dataDirStr+"/"+CONSTRAINTS_JSON_FILE)

	// Read the R1CS.
	r1csFile, err := os.Open(dataDirStr + "/" + CIRCUIT_PATH)
	if err != nil {
		panic(err)
	}
	r1cs := groth16.NewCS(ecc.BN254)
	r1cs.ReadFrom(r1csFile)

	// Read the proving key.
	pkFile, err := os.Open(dataDirStr + "/" + PK_PATH)
	if err != nil {
		panic(err)
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	pk.ReadDump(pkFile)

	// Read the verifier key.
	vkFile, err := os.Open(dataDirStr + "/" + VK_PATH)
	if err != nil {
		panic(err)
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	vk.ReadFrom(vkFile)

	// Read the file.
	data, err := os.ReadFile(witnessPathStr)
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

	sp1Groth16Proof := sp1.NewSP1Groth16Proof(&proof, witnessInput)
	// // Serialize the proof to a file.
	// jsonData, err := json.Marshal(sp1Groth16Proof)
	// if err != nil {
	// 	panic(err)
	// }
	// err = os.WriteFile(proofPathStr, jsonData, 0644)
	// if err != nil {
	// 	panic(err)
	// }

	// cProof := C.C_Groth16Proof{
	// 	PublicInputs: [2]*C.char{C.CString(sp1Groth16Proof.PublicInputs[0]), C.CString(sp1Groth16Proof.PublicInputs[1])},
	// 	EncodedProof: C.CString(sp1Groth16Proof.EncodedProof),
	// 	RawProof:     C.CString(sp1Groth16Proof.RawProof),
	// }

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

	// Set the enviroment variable for the constraints file.
	//
	// TODO: There might be some non-determinism if a single processe is running this command
	// multiple times.
	os.Setenv("CONSTRAINTS_JSON", dataDirString+"/"+CONSTRAINTS_JSON_FILE)

	// Read the file.
	witnessInputPath := dataDirString + "/witness_groth16.json"
	data, err := os.ReadFile(witnessInputPath)
	if err != nil {
		panic(err)
	}

	// Deserialize the JSON data into a slice of Instruction structs
	var witnessInput sp1.WitnessInput
	err = json.Unmarshal(data, &witnessInput)
	if err != nil {
		panic(err)
	}

	// Initialize the circuit.
	circuit := sp1.NewCircuit(witnessInput)

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
	assignment := sp1.NewCircuit(witnessInput)
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
	os.MkdirAll(dataDirString, 0755)

	// Write the solidity verifier.
	solidityVerifierFile, err := os.Create(dataDirString + "/" + VERIFIER_CONTRACT_PATH)
	if err != nil {
		panic(err)
	}
	vk.ExportSolidity(solidityVerifierFile)

	// Write the R1CS.
	r1csFile, err := os.Create(dataDirString + "/" + CIRCUIT_PATH)
	if err != nil {
		panic(err)
	}
	defer r1csFile.Close()
	_, err = r1cs.WriteTo(r1csFile)
	if err != nil {
		panic(err)
	}

	// Write the verifier key.
	vkFile, err := os.Create(dataDirString + "/" + VK_PATH)
	if err != nil {
		panic(err)
	}
	defer vkFile.Close()
	_, err = vk.WriteTo(vkFile)
	if err != nil {
		panic(err)
	}

	// Write the proving key.
	pkFile, err := os.Create(dataDirString + "/" + PK_PATH)
	if err != nil {
		panic(err)
	}
	defer pkFile.Close()
	pk.WriteDump(pkFile)
}
