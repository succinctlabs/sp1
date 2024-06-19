package sp1

import (
	"bytes"
	"encoding/hex"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1/babybear"
)

func Verify(verifyCmdDataDir string, verifyCmdProof string, verifyCmdVkeyHash string, verifyCmdCommitedValuesDigest string) error {
	// Sanity check the required arguments have been provided.
	if verifyCmdDataDir == "" {
		panic("--data is required")
	}

	// Decode the proof.
	proofDecodedBytes, err := hex.DecodeString(verifyCmdProof)
	if err != nil {
		panic(err)
	}
	proof := plonk.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(proofDecodedBytes)); err != nil {
		panic(err)
	}

	// Read the verifier key.
	vkFile, err := os.Open(verifyCmdDataDir + "/" + vkPath)
	if err != nil {
		panic(err)
	}
	vk := plonk.NewVerifyingKey(ecc.BN254)
	vk.ReadFrom(vkFile)

	// Compute the public witness.
	circuit := Circuit{
		Vars:                 []frontend.Variable{},
		Felts:                []babybear.Variable{},
		Exts:                 []babybear.ExtensionVariable{},
		VkeyHash:             verifyCmdVkeyHash,
		CommitedValuesDigest: verifyCmdCommitedValuesDigest,
	}
	witness, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	// Verify proof.
	err = plonk.Verify(proof, vk, publicWitness)
	return err
}
