package main

/*
#cgo LDFLAGS: ./lib/libbabybear.a -ldl
#include "./lib/babybear.h"
*/
import "C"

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

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
		os.Setenv("CONSTRAINTS_JSON", buildDir+"/constraints_groth16.json")

		sp1.BuildGroth16(buildDir)

	case BuildPlonkBn254:
		buildPlonkBn254Cmd.Parse(os.Args[2:])
		fmt.Printf("Running 'build' with data=%s\n", *buildPlonkBn254DataDirFlag)
		buildDir := *buildPlonkBn254DataDirFlag
		os.Setenv("CONSTRAINTS_JSON", buildDir+"/constraints_plonk_bn254.json")

		err := sp1.BuildPlonkBn254(buildDir)
		if err != nil {
			panic(err)
		}
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

		// Verify the hex-encoded groth16 proof with the given vkey hash and committed values digest
		// as public inputs.
		err := sp1.VerifyGroth16(buildDir, hexEncodedProof, vkeyHash, commitedValuesDigest)
		if err != nil {
			panic(err)
		}
	case ConvertGroth16:
		// Parse the flags for converting the gnark groth16 proof representation to a format that
		// can be used with Solidity smart contract verification.
		convertGroth16Cmd.Parse(os.Args[2:])
		fmt.Printf("Running 'convert' with data=%s\n", *convertGroth16DataDirFlag)
		dataDir := *convertGroth16DataDirFlag
		hexEncodedProof := *convertGroth16EncodedProofFlag
		vkeyHash := *convertGroth16VkeyHashFlag
		commitedValuesDigest := *convertGroth16CommitedValuesDigestFlag

		// Convert the gnark groth16 proof to a format that can be used with Solidity smart contract verification.
		err := sp1.ConvertGroth16(dataDir, hexEncodedProof, vkeyHash, commitedValuesDigest)
		if err != nil {
			panic(err)
		}
	case ProvePlonkBn254:
		// Parse the flags for generating a Plonk proof.
		provePlonkBn254Cmd.Parse(os.Args[2:])
		fmt.Printf("Running 'prove' with data=%s\n", *provePlonkBn254DataDirFlag)
		buildDir := *provePlonkBn254DataDirFlag
		witnessPath := *provePlonkBn254WitnessPathFlag
		proofPath := *provePlonkBn254ProofPathFlag
		os.Setenv("CONSTRAINTS_JSON", buildDir+"/constraints_plonk_bn254.json")

		// Generate the Plonk proof.
		err := sp1.ProvePlonkBn254(buildDir, witnessPath, proofPath)
		if err != nil {
			panic(err)
		}

	case Serve:
		serveCmd.Parse(os.Args[2:])
		fmt.Printf("[sp1] running 'serve' with data=%s, type=%s\n", *serveCircuitDataDirFlag, *serveCircuitTypeFlag)
		circuitDataDir := *serveCircuitDataDirFlag
		circuitType := *serveCircuitTypeFlag
		serveHostPort := *servePortFlag
		os.Setenv("CONSTRAINTS_JSON", circuitDataDir+"/constraints_groth16.json")

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
