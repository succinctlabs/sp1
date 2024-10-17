package sp1

import (
	"bytes"
	"encoding/hex"

	groth16 "github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	plonk "github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1/babybear"
)

func NewSP1PlonkBn254Proof(proof *plonk.Proof, witnessInput WitnessInput) Proof {
	var buf bytes.Buffer
	(*proof).WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	var publicInputs [2]string
	publicInputs[0] = witnessInput.VkeyHash
	publicInputs[1] = witnessInput.CommittedValuesDigest

	// Cast plonk proof into plonk_bn254 proof so we can call MarshalSolidity.
	p := (*proof).(*plonk_bn254.Proof)

	encodedProof := p.MarshalSolidity()

	return Proof{
		PublicInputs: publicInputs,
		EncodedProof: hex.EncodeToString(encodedProof),
		RawProof:     hex.EncodeToString(proofBytes),
	}
}

func NewSP1Groth16Proof(proof *groth16.Proof, witnessInput WitnessInput) Proof {
	var buf bytes.Buffer
	(*proof).WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	var publicInputs [2]string
	publicInputs[0] = witnessInput.VkeyHash
	publicInputs[1] = witnessInput.CommittedValuesDigest

	// Cast groth16 proof into groth16_bn254 proof so we can call MarshalSolidity.
	p := (*proof).(*groth16_bn254.Proof)

	encodedProof := p.MarshalSolidity()

	return Proof{
		PublicInputs: publicInputs,
		EncodedProof: hex.EncodeToString(encodedProof),
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
		CommittedValuesDigest: witnessInput.CommittedValuesDigest,
		Vars:                 vars,
		Felts:                felts,
		Exts:                 exts,
	}
}
