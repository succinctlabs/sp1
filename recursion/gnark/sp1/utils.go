package sp1

import (
	"bytes"
	"encoding/hex"
	"math/big"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1/babybear"
)

func NewSP1Groth16Proof(proof *groth16.Proof, witnessInput WitnessInput) Groth16Proof {
	var buf bytes.Buffer
	(*proof).WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	fpSize := 4 * 8
	var (
		a [2]*big.Int
		b [2][2]*big.Int
		c [2]*big.Int
	)
	a[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	a[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	b[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	b[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	b[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	b[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	c[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	c[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])

	commitmentCountBigInt := new(big.Int).SetBytes(proofBytes[fpSize*8 : fpSize*8+4])
	commitmentCount := int(commitmentCountBigInt.Int64())

	var commitments []*big.Int = make([]*big.Int, 2*commitmentCount)
	var commitmentPok [2]*big.Int

	for i := 0; i < 2*commitmentCount; i++ {
		commitments[i] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+i*fpSize : fpSize*8+4+(i+1)*fpSize])
	}

	commitmentPok[0] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize : fpSize*8+4+2*commitmentCount*fpSize+fpSize])
	commitmentPok[1] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize+fpSize : fpSize*8+4+2*commitmentCount*fpSize+2*fpSize])

	var publicInputs [2]string
	publicInputs[0] = witnessInput.VkeyHash
	publicInputs[1] = witnessInput.CommitedValuesDigest
	encodedProof := hex.EncodeToString(proofBytes)

	return Groth16Proof{
		PublicInputs: publicInputs,
		EncodedProof: encodedProof,
		RawProof:     hex.EncodeToString(proofBytes),
	}
}

func NewCircuit(witnessInput WitnessInput) Circuit {
	vars := make([]frontend.Variable, len(witnessInput.Vars))
	felts := make([]babybear.Variable, len(witnessInput.Felts))
	exts := make([]babybear.ExtensionVariable, len(witnessInput.Exts))
	for i := 0; i < len(witnessInput.Vars); i++ {
		vars[i] = frontend.Variable(witnessInput.Vars[i])
	}
	for i := 0; i < len(witnessInput.Felts); i++ {
		felts[i] = babybear.NewF(witnessInput.Felts[i])
	}
	for i := 0; i < len(witnessInput.Exts); i++ {
		exts[i] = babybear.NewE(witnessInput.Exts[i])
	}
	return Circuit{
		VkeyHash:             witnessInput.VkeyHash,
		CommitedValuesDigest: witnessInput.CommitedValuesDigest,
		Vars:                 vars,
		Felts:                felts,
		Exts:                 exts,
	}
}
