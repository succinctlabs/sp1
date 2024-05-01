package main

/*
#cgo LDFLAGS: ./lib/libbabybear.a -ldl
#include "./lib/babybear.h"
*/
import "C"

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/succinctlabs/sp1-recursion-gnark/server"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1"
)

const (
	BuildGroth16    = "build-groth16"
	BuildPlonkBn254 = "build-plonk-bn254"
	ProveGroth16    = "prove-groth16"
	VerifyGroth16   = "verify-groth16"
	ConvertGroth16  = "convert-groth16"
	ProvePlonkBn254 = "prove-plonk-bn254"
	Serve           = "serve"
)

func main() {
	buildGroth16Cmd := flag.NewFlagSet(BuildGroth16, flag.ExitOnError)
	buildGroth16DataDirFlag := buildGroth16Cmd.String("data", "", "Data directory path")
	buildGroth16ProfileFlag := buildGroth16Cmd.Bool("profile", false, "Profile the circuit")

	buildPlonkBn254Cmd := flag.NewFlagSet(BuildPlonkBn254, flag.ExitOnError)
	buildPlonkBn254DataDirFlag := buildPlonkBn254Cmd.String("data", "", "Data directory path")

	proveGroth16Cmd := flag.NewFlagSet(ProveGroth16, flag.ExitOnError)
	proveGroth16DataDirFlag := proveGroth16Cmd.String("data", "", "Data directory path")
	proveGroth16WitnessPathFlag := proveGroth16Cmd.String("witness", "", "Path to witness")
	proveGroth16ProofPathFlag := proveGroth16Cmd.String("proof", "", "Path to proof")

	verifyGroth16Cmd := flag.NewFlagSet(VerifyGroth16, flag.ExitOnError)
	verifyGroth16DataDirFlag := verifyGroth16Cmd.String("data", "", "Data directory path")
	verifyGroth16EncodedProofFlag := verifyGroth16Cmd.String("encoded-proof", "", "Encoded proof")
	verifyGroth16VkeyHashFlag := verifyGroth16Cmd.String("vkey-hash", "", "Vkey hash")
	verifyGroth16CommitedValuesDigestFlag := verifyGroth16Cmd.String("commited-values-digest", "", "Commited values digest")

	convertGroth16Cmd := flag.NewFlagSet(ConvertGroth16, flag.ExitOnError)
	convertGroth16DataDirFlag := convertGroth16Cmd.String("data", "", "Data directory path")
	convertGroth16EncodedProofFlag := convertGroth16Cmd.String("encoded-proof", "", "Encoded proof")
	convertGroth16VkeyHashFlag := convertGroth16Cmd.String("vkey-hash", "", "Vkey hash")
	convertGroth16CommitedValuesDigestFlag := convertGroth16Cmd.String("commited-values-digest", "", "Commited values digest")

	provePlonkBn254Cmd := flag.NewFlagSet(ProvePlonkBn254, flag.ExitOnError)
	provePlonkBn254DataDirFlag := provePlonkBn254Cmd.String("data", "", "Data directory path")
	provePlonkBn254WitnessPathFlag := provePlonkBn254Cmd.String("witness", "", "Path to witness")
	provePlonkBn254ProofPathFlag := provePlonkBn254Cmd.String("proof", "", "Path to proof")

	serveCmd := flag.NewFlagSet(Serve, flag.ExitOnError)
	serveCircuitDataDirFlag := serveCmd.String("data", "", "Data directory path")
	serveCircuitTypeFlag := serveCmd.String("type", "", "Type of circuit to download from if it is not in the data directory")
	servePortFlag := serveCmd.String("port", "8080", "host port to listen on")

	if len(os.Args) < 2 {
		// Join the subcommands together with a comma.
		subcommands := strings.Join([]string{BuildGroth16, ProveGroth16, VerifyGroth16, ConvertGroth16, ProvePlonkBn254, Serve}, ", ")

		fmt.Printf("expected one of the subcommands: %s\n", subcommands)
		os.Exit(1)
	}

	switch os.Args[1] {
	case BuildGroth16:
		buildGroth16Cmd.Parse(os.Args[2:])
		fmt.Printf("Running 'build' with data=%s\n", *buildGroth16DataDirFlag)
		buildDir := *buildGroth16DataDirFlag
		profileFlag := *buildGroth16ProfileFlag
		os.Setenv("CONSTRAINTS_JSON", buildDir+"/constraints_groth16.json")

		sp1.BuildGroth16(buildDir, profileFlag)

	case BuildPlonkBn254:
		buildPlonkBn254Cmd.Parse(os.Args[2:])
		fmt.Printf("Running 'build' with data=%s\n", *buildPlonkBn254DataDirFlag)
		buildDir := *buildPlonkBn254DataDirFlag
		os.Setenv("CONSTRAINTS_JSON", buildDir+"/constraints_plonk_bn254.json")

		// Load the witness input.
		witnessInput, err := sp1.LoadWitnessInputFromPath(buildDir + "/witness_plonk_bn254.json")
		if err != nil {
			panic(err)
		}

		// Initialize the circuit.
		circuit := sp1.NewCircuitFromWitness(witnessInput)

		// Compile the circuit.
		builder := scs.NewBuilder
		scs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
		if err != nil {
			panic(err)
		}

		// Sourced from: https://github.com/Consensys/gnark/blob/88712e5ce5dbbb6a1efca23b659f967d36261de4/examples/plonk/main.go#L86-L89
		srs, srsLagrange, err := unsafekzg.NewSRS(scs)
		if err != nil {
			panic(err)
		}

		pk, vk, err := plonk.Setup(scs, srs, srsLagrange)
		if err != nil {
			panic(err)
		}

		// Create the build directory.
		os.MkdirAll(buildDir, 0755)

		// Write the R1CS.
		sp1.WriteToFile(buildDir+"/circuit_plonk_bn254.bin", scs)

		// Write the proving key.
		sp1.WriteToFile(buildDir+"/pk_plonk_bn254.bin", pk)

		// Write the verifier key.
		sp1.WriteToFile(buildDir+"/vk_plonk_bn254.bin", vk)

		// Write the solidity verifier.
		solidityVerifierFile, err := os.Create(buildDir + "/PlonkBn254Verifier.sol")
		if err != nil {
			panic(err)
		}
		vk.ExportSolidity(solidityVerifierFile)
	case ProveGroth16:
		proveGroth16Cmd.Parse(os.Args[2:])
		fmt.Printf("Running 'prove' with data=%s\n", *proveGroth16DataDirFlag)
		buildDir := *proveGroth16DataDirFlag
		witnessPath := *proveGroth16WitnessPathFlag
		proofPath := *proveGroth16ProofPathFlag
		os.Setenv("CONSTRAINTS_JSON", buildDir+"/constraints_groth16.json")

		err := sp1.ProveGroth16(buildDir, witnessPath, proofPath)
		if err != nil {
			panic(err)
		}
	case VerifyGroth16:
		verifyGroth16Cmd.Parse(os.Args[2:])
		fmt.Printf("Running 'verify' with data=%s\n", *verifyGroth16DataDirFlag)
		buildDir := *verifyGroth16DataDirFlag
		hexEncodedProof := *verifyGroth16EncodedProofFlag
		vkeyHash := *verifyGroth16VkeyHashFlag
		commitedValuesDigest := *verifyGroth16CommitedValuesDigestFlag

		err := sp1.VerifyGroth16(buildDir, hexEncodedProof, vkeyHash, commitedValuesDigest)
		if err != nil {
			panic(err)
		}
	case ConvertGroth16:
		convertGroth16Cmd.Parse(os.Args[2:])
		fmt.Printf("Running 'convert' with data=%s\n", *convertGroth16DataDirFlag)
		dataDir := *convertGroth16DataDirFlag
		hexEncodedProof := *convertGroth16EncodedProofFlag
		vkeyHash := *convertGroth16VkeyHashFlag
		commitedValuesDigest := *convertGroth16CommitedValuesDigestFlag

		err := sp1.VerifyGroth16(dataDir, hexEncodedProof, vkeyHash, commitedValuesDigest)
		if err != nil {
			panic(err)
		}
	case ProvePlonkBn254:
		provePlonkBn254Cmd.Parse(os.Args[2:])
		fmt.Printf("Running 'prove' with data=%s\n", *provePlonkBn254DataDirFlag)
		buildDir := *provePlonkBn254DataDirFlag
		witnessPath := *provePlonkBn254WitnessPathFlag
		proofPath := *provePlonkBn254ProofPathFlag
		os.Setenv("CONSTRAINTS_JSON", buildDir+"/constraints_plonk_bn254.json")

		// Read the R1CS.
		fmt.Println("Reading scs...")
		scsFile, err := os.Open(buildDir + "/circuit_plonk_bn254.bin")
		if err != nil {
			panic(err)
		}
		scs := plonk.NewCS(ecc.BN254)
		scs.ReadFrom(scsFile)

		// Read the proving key.
		fmt.Println("Reading pk...")
		pkFile, err := os.Open(buildDir + "/pk_plonk_bn254.bin")
		if err != nil {
			panic(err)
		}
		pk := plonk.NewProvingKey(ecc.BN254)
		pk.ReadFrom(pkFile)

		// Read the verifier key.
		fmt.Println("Reading vk...")
		vkFile, err := os.Open(buildDir + "/vk_plonk_bn254.bin")
		if err != nil {
			panic(err)
		}
		vk := plonk.NewVerifyingKey(ecc.BN254)
		vk.ReadFrom(vkFile)

		// Generate the witness.
		witnessInput, err := sp1.LoadWitnessInputFromPath(witnessPath)
		if err != nil {
			panic(err)
		}
		assignment := sp1.NewCircuitFromWitness(witnessInput)
		witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
		if err != nil {
			panic(err)
		}

		// Generate the proof.
		fmt.Println("Generating proof...")
		proof, err := plonk.Prove(scs, pk, witness)
		if err != nil {
			panic(err)
		}

		plonkBn254ProofRaw := proof.(*plonk_bn254.Proof)
		plonkBn254Proof := sp1.PlonkBn254Proof{
			Proof: "0x" + hex.EncodeToString(plonkBn254ProofRaw.MarshalSolidity()),
			PublicInputs: [2]string{
				witnessInput.VkeyHash,
				witnessInput.CommitedValuesDigest,
			},
		}

		jsonData, err := json.Marshal(plonkBn254Proof)
		if err != nil {
			panic(err)
		}

		err = os.WriteFile(proofPath, jsonData, 0644)
		if err != nil {
			panic(err)
		}
	case Serve:
		serveCmd.Parse(os.Args[2:])
		fmt.Printf("Running 'serve' with data=%s, type=%s\n", *serveCircuitDataDirFlag, *serveCircuitTypeFlag)
		circuitDataDir := *serveCircuitDataDirFlag
		circuitType := *serveCircuitTypeFlag
		serveHostPort := *servePortFlag

		if circuitDataDir == "" || circuitType == "" || serveHostPort == "" {
			fmt.Println("Error: data directory, type, and host port flags are all required")
			os.Exit(1)
		}
		s, err := server.New(context.Background(), circuitDataDir, circuitType)
		if err != nil {
			panic(fmt.Errorf("initializing server: %w", err))
		}
		s.Start(serveHostPort)

	default:
		fmt.Println("expected 'prove' or 'build' subcommand")
		os.Exit(1)
	}
}
