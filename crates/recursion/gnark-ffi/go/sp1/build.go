package sp1

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	groth16 "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1/trusted_setup"
)

func BuildPlonk(dataDir string) {
	// Set the environment variable for the constraints file.
	//
	// TODO: There might be some non-determinism if a single process is running this command
	// multiple times.
	os.Setenv("CONSTRAINTS_JSON", dataDir+"/"+constraintsJsonFile)

	// Read the file.
	witnessInputPath := dataDir + "/" + plonkWitnessPath
	data, err := os.ReadFile(witnessInputPath)
	if err != nil {
		panic(err)
	}

	// Deserialize the JSON data into a slice of Instruction structs
	var witnessInput WitnessInput
	err = json.Unmarshal(data, &witnessInput)
	if err != nil {
		panic(err)
	}

	// Initialize the circuit.
	circuit := NewCircuit(witnessInput)

	// Compile the circuit.
	scs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	// Download the trusted setup.
	var srs kzg.SRS = kzg.NewSRS(ecc.BN254)
	var srsLagrange kzg.SRS = kzg.NewSRS(ecc.BN254)
	srsFileName := dataDir + "/" + srsFile
	srsLagrangeFileName := dataDir + "/" + srsLagrangeFile

	srsLagrangeFile, err := os.Create(srsLagrangeFileName)
	if err != nil {
		log.Fatal("error creating srs file: ", err)
		panic(err)
	}
	defer srsLagrangeFile.Close()

	if !strings.Contains(dataDir, "dev") {
		if _, err := os.Stat(srsFileName); os.IsNotExist(err) {
			fmt.Println("downloading aztec ignition srs")
			trusted_setup.DownloadAndSaveAztecIgnitionSrs(174, srsFileName)

			srsFile, err := os.Open(srsFileName)
			if err != nil {
				panic(err)
			}
			defer srsFile.Close()

			_, err = srs.ReadFrom(srsFile)
			if err != nil {
				panic(err)
			}

			srsLagrange = trusted_setup.ToLagrange(scs, srs)
			_, err = srsLagrange.WriteTo(srsLagrangeFile)
			if err != nil {
				panic(err)
			}
		} else {
			srsFile, err := os.Open(srsFileName)
			if err != nil {
				panic(err)
			}
			defer srsFile.Close()

			_, err = srs.ReadFrom(srsFile)
			if err != nil {
				panic(err)
			}

			_, err = srsLagrange.ReadFrom(srsLagrangeFile)
			if err != nil {
				panic(err)
			}

		}
	} else {
		srs, srsLagrange, err = unsafekzg.NewSRS(scs)
		if err != nil {
			panic(err)
		}

		srsFile, err := os.Create(srsFileName)
		if err != nil {
			panic(err)
		}
		defer srsFile.Close()

		_, err = srs.WriteTo(srsFile)
		if err != nil {
			panic(err)
		}

		_, err = srsLagrange.WriteTo(srsLagrangeFile)
		if err != nil {
			panic(err)
		}
	}

	// Generate the proving and verifying key.
	pk, vk, err := plonk.Setup(scs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}

	// Generate proof.
	assignment := NewCircuit(witnessInput)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	proof, err := plonk.Prove(scs, pk, witness)
	if err != nil {
		panic(err)
	}

	// Verify proof.
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}
	err = plonk.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}

	// Create the build directory.
	os.MkdirAll(dataDir, 0755)

	// Write the solidity verifier.
	solidityVerifierFile, err := os.Create(dataDir + "/" + plonkVerifierContractPath)
	if err != nil {
		panic(err)
	}
	vk.ExportSolidity(solidityVerifierFile)
	defer solidityVerifierFile.Close()

	// Write the R1CS.
	scsFile, err := os.Create(dataDir + "/" + plonkCircuitPath)
	if err != nil {
		panic(err)
	}
	defer scsFile.Close()
	_, err = scs.WriteTo(scsFile)
	if err != nil {
		panic(err)
	}

	// Write the verifier key.
	vkFile, err := os.Create(dataDir + "/" + plonkVkPath)
	if err != nil {
		panic(err)
	}
	defer vkFile.Close()
	_, err = vk.WriteTo(vkFile)
	if err != nil {
		panic(err)
	}

	// Write the proving key.
	pkFile, err := os.Create(dataDir + "/" + plonkPkPath)
	if err != nil {
		panic(err)
	}
	defer pkFile.Close()
	_, err = pk.WriteTo(pkFile)
	if err != nil {
		panic(err)
	}
}

func BuildGroth16(dataDir string) {
	// Set the environment variable for the constraints file.
	//
	// TODO: There might be some non-determinism if a single process is running this command
	// multiple times.
	os.Setenv("CONSTRAINTS_JSON", dataDir+"/"+constraintsJsonFile)
	os.Setenv("GROTH16", "1")

	// Read the file.
	witnessInputPath := dataDir + "/" + groth16WitnessPath
	data, err := os.ReadFile(witnessInputPath)
	if err != nil {
		panic(err)
	}

	// Deserialize the JSON data into a slice of Instruction structs
	var witnessInput WitnessInput
	err = json.Unmarshal(data, &witnessInput)
	if err != nil {
		panic(err)
	}

	// Initialize the circuit.
	circuit := NewCircuit(witnessInput)

	// Compile the circuit.
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	// Generate the proving and verifying key.
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		panic(err)
	}

	// Generate proof.
	assignment := NewCircuit(witnessInput)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		panic(err)
	}

	// Verify proof.
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}

	// Create the build directory.
	os.MkdirAll(dataDir, 0755)

	// Write the solidity verifier.
	solidityVerifierFile, err := os.Create(dataDir + "/" + groth16VerifierContractPath)
	if err != nil {
		panic(err)
	}
	vk.ExportSolidity(solidityVerifierFile)
	defer solidityVerifierFile.Close()

	// Write the R1CS.
	r1csFile, err := os.Create(dataDir + "/" + groth16CircuitPath)
	if err != nil {
		panic(err)
	}
	defer r1csFile.Close()
	_, err = r1cs.WriteTo(r1csFile)
	if err != nil {
		panic(err)
	}

	// Write the verifier key.
	vkFile, err := os.Create(dataDir + "/" + groth16VkPath)
	if err != nil {
		panic(err)
	}
	defer vkFile.Close()
	_, err = vk.WriteTo(vkFile)
	if err != nil {
		panic(err)
	}

	// Write the proving key.
	pkFile, err := os.Create(dataDir + "/" + groth16PkPath)
	if err != nil {
		panic(err)
	}
	defer pkFile.Close()
	err = pk.WriteDump(pkFile)
	if err != nil {
		panic(err)
	}
}
