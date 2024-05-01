package main

/*
#cgo LDFLAGS: ./lib/libbabybear.a -ldl
#include "./lib/babybear.h"
*/
import "C"

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/test"
	"github.com/succinctlabs/sp1-recursion-gnark/server"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1"
)

func main() {
	buildGroth16Cmd := flag.NewFlagSet("build-groth16", flag.ExitOnError)
	buildGroth16DataDirFlag := buildGroth16Cmd.String("data", "", "Data directory path")
	buildGroth16ProfileFlag := buildGroth16Cmd.Bool("profile", false, "Profile the circuit")

	buildPlonkBn254Cmd := flag.NewFlagSet("build-plonk-bn254", flag.ExitOnError)
	buildPlonkBn254DataDirFlag := buildPlonkBn254Cmd.String("data", "", "Data directory path")

	proveGroth16Cmd := flag.NewFlagSet("prove-groth16", flag.ExitOnError)
	proveGroth16DataDirFlag := proveGroth16Cmd.String("data", "", "Data directory path")
	proveGroth16WitnessPathFlag := proveGroth16Cmd.String("witness", "", "Path to witness")
	proveGroth16ProofPathFlag := proveGroth16Cmd.String("proof", "", "Path to proof")

	provePlonkBn254Cmd := flag.NewFlagSet("prove-plonk-bn254", flag.ExitOnError)
	provePlonkBn254DataDirFlag := provePlonkBn254Cmd.String("data", "", "Data directory path")
	provePlonkBn254WitnessPathFlag := provePlonkBn254Cmd.String("witness", "", "Path to witness")
	provePlonkBn254ProofPathFlag := provePlonkBn254Cmd.String("proof", "", "Path to proof")

	serveCmd := flag.NewFlagSet("serve", flag.ExitOnError)
	serveCircuitDataDirFlag := serveCmd.String("data", "", "Data directory path")
	serveCircuitTypeFlag := serveCmd.String("type", "", "Type of circuit to download from if it is not in the data directory")
	servePortFlag := serveCmd.String("port", "8080", "host port to listen on")

	if len(os.Args) < 2 {
		fmt.Println("expected 'build-groth16', 'prove-groth16', 'build-plonk-bn254', 'prove-plonk-bn254', or 'serve' subcommand")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "build-groth16":
		buildGroth16Cmd.Parse(os.Args[2:])
		fmt.Printf("Running 'build' with data=%s\n", *buildGroth16DataDirFlag)
		buildDir := *buildGroth16DataDirFlag
		os.Setenv("CONSTRAINTS_JSON", buildDir+"/constraints_groth16.json")

		// Load the witness input.
		witnessInput, err := sp1.LoadWitnessInputFromPath(buildDir + "/witness_groth16.json")
		if err != nil {
			panic(err)
		}

		// Initialize the circuit.
		circuit := sp1.NewCircuitFromWitness(witnessInput)

		// Profile the circuit.
		var p *profile.Profile
		if *buildGroth16ProfileFlag {
			p = profile.Start()
		}

		// Compile the circuit.
		builder := r1cs.NewBuilder
		r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
		if err != nil {
			panic(err)
		}
		fmt.Println("NbConstraints:", r1cs.GetNbConstraints())

		// Stop the profiler.
		if *buildGroth16ProfileFlag {
			p.Stop()
			report := p.Top()
			reportFile, err := os.Create(buildDir + "/profile_groth16.pprof")
			if err != nil {
				panic(err)
			}
			reportFile.WriteString(report)
			reportFile.Close()
		}

		// Run the trusted setup.
		var pk groth16.ProvingKey
		pk, vk, err := groth16.Setup(r1cs)
		if err != nil {
			panic(err)
		}

		// Create the build directory.
		os.MkdirAll(buildDir, 0755)

		// Write the R1CS.
		r1csFile, err := os.Create(buildDir + "/circuit_groth16.bin")
		if err != nil {
			panic(err)
		}
		r1cs.WriteTo(r1csFile)
		r1csFile.Close()

		// Write the proving key.
		pkFile, err := os.Create(buildDir + "/pk_groth16.bin")
		if err != nil {
			panic(err)
		}
		pk.WriteTo(pkFile)
		pkFile.Close()

		// Write the verifier key.
		vkFile, err := os.Create(buildDir + "/vk_groth16.bin")
		if err != nil {
			panic(err)
		}
		vk.WriteTo(vkFile)
		vkFile.Close()

		// Write the solidity verifier.
		solidityVerifierFile, err := os.Create(buildDir + "/Groth16Verifier.sol")
		if err != nil {
			panic(err)
		}
		vk.ExportSolidity(solidityVerifierFile)
	case "build-plonk-bn254":
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

		// Run the trusted setup.
		srs, err := test.NewKZGSRS(scs)
		if err != nil {
			panic(err)
		}

		pk, vk, err := plonk.Setup(scs, srs)
		if err != nil {
			panic(err)
		}

		// Create the build directory.
		os.MkdirAll(buildDir, 0755)

		// Write the R1CS.
		scsFile, err := os.Create(buildDir + "/circuit_plonk_bn254.bin")
		if err != nil {
			panic(err)
		}
		scs.WriteTo(scsFile)
		scsFile.Close()

		// Write the proving key.
		pkFile, err := os.Create(buildDir + "/pk_plonk_bn254.bin")
		if err != nil {
			panic(err)
		}
		pk.WriteTo(pkFile)
		pkFile.Close()

		// Write the verifier key.
		vkFile, err := os.Create(buildDir + "/vk_plonk_bn254.bin")
		if err != nil {
			panic(err)
		}
		vk.WriteTo(vkFile)
		vkFile.Close()

		// Write the solidity verifier.
		solidityVerifierFile, err := os.Create(buildDir + "/PlonkBn254Verifier.sol")
		if err != nil {
			panic(err)
		}
		vk.ExportSolidity(solidityVerifierFile)
	case "prove-groth16":
		proveGroth16Cmd.Parse(os.Args[2:])
		fmt.Printf("Running 'prove' with data=%s\n", *proveGroth16DataDirFlag)
		buildDir := *proveGroth16DataDirFlag
		witnessPath := *proveGroth16WitnessPathFlag
		proofPath := *proveGroth16ProofPathFlag
		os.Setenv("CONSTRAINTS_JSON", buildDir+"/constraints_groth16.json")

		// Read the R1CS.
		fmt.Println("Reading r1cs...")
		r1csFile, err := os.Open(buildDir + "/circuit_groth16.bin")
		if err != nil {
			panic(err)
		}
		r1cs := groth16.NewCS(ecc.BN254)
		r1cs.ReadFrom(r1csFile)

		// Read the proving key.
		fmt.Println("Reading pk...")
		pkFile, err := os.Open(buildDir + "/pk_groth16.bin")
		if err != nil {
			panic(err)
		}
		pk := groth16.NewProvingKey(ecc.BN254)
		pk.ReadFrom(pkFile)

		// Read the verifier key.
		fmt.Println("Reading vk...")
		vkFile, err := os.Open(buildDir + "/vk_groth16.bin")
		if err != nil {
			panic(err)
		}
		vk := groth16.NewVerifyingKey(ecc.BN254)
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
		publicWitness, err := witness.Public()
		if err != nil {
			panic(err)
		}

		// Generate the proof.
		fmt.Println("Generating proof...")
		proof, err := groth16.Prove(r1cs, pk, witness)
		if err != nil {
			panic(err)
		}

		fmt.Println("Verifying proof...")
		err = groth16.Verify(proof, vk, publicWitness)
		if err != nil {
			panic(err)
		}

		// Serialize the proof to JSON.
		const fpSize = 4 * 8
		var buf bytes.Buffer
		proof.WriteRawTo(&buf)
		proofBytes := buf.Bytes()
		var (
			a            [2]string
			b            [2][2]string
			c            [2]string
			publicInputs [2]string
		)
		a[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1]).String()
		a[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2]).String()
		b[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3]).String()
		b[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4]).String()
		b[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5]).String()
		b[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6]).String()
		c[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7]).String()
		c[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8]).String()
		publicInputs[0] = witnessInput.VkeyHash
		publicInputs[1] = witnessInput.CommitedValuesDigest

		groth16Proof := sp1.Groth16Proof{
			A:            a,
			B:            b,
			C:            c,
			PublicInputs: publicInputs,
		}

		jsonData, err := json.Marshal(groth16Proof)
		if err != nil {
			panic(err)
		}

		err = os.WriteFile(proofPath, jsonData, 0644)
		if err != nil {
			panic(err)
		}
	case "prove-plonk-bn254":
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
	case "serve":
		serveCmd.Parse(os.Args[2:])
		fmt.Printf("Running 'serve' with data=%s, type=%s\n", *serveCircuitDataDirFlag, *serveCircuitTypeFlag)
		circuitDataDir := *serveCircuitDataDirFlag
		circuitType := *serveCircuitTypeFlag
		serveHostPort := *servePortFlag

		if circuitDataDir == "" {
			fmt.Println("Error: data directory flag is required")
			os.Exit(1)
		}
		if circuitType == "" {
			fmt.Println("Error: type flag is required")
			os.Exit(1)
		}
		if serveHostPort == "" {
			fmt.Println("Error: host port flag is required")
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
