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
	"github.com/consensys/gnark/backend/groth16"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1"
)

func main() {}

var CircuitDataMap = make(map[uint32]groth16.ProvingKey)

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
