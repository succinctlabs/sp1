//go:build cuda

package sp1

import (
	"bufio"
	"encoding/json"
	"os"
	"runtime/debug"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1/gpu"
)

var (
	groth16CudaMu      sync.Mutex
	groth16CudaProvers = map[string]*gpu.Groth16Prover{}
)

// loadGroth16CudaProver keeps the circuit and its proving key in host memory for the life of the process.
func loadGroth16CudaProver(dataDir string) *gpu.Groth16Prover {
	if p, ok := groth16CudaProvers[dataDir]; ok {
		return p
	}
	r1cs := groth16.NewCS(ecc.BN254)
	if err := readCircuit(dataDir+"/"+groth16CircuitPath, r1cs); err != nil {
		panic(err)
	}
	pkFile, err := os.Open(dataDir + "/" + groth16PkPath)
	if err != nil {
		panic(err)
	}
	defer pkFile.Close()
	pk := groth16.NewProvingKey(ecc.BN254)
	if err := pk.ReadDump(bufio.NewReaderSize(pkFile, 1024*1024)); err != nil {
		panic(err)
	}
	p := gpu.NewGroth16Prover(r1cs.(*cs.R1CS), pk.(*groth16_bn254.ProvingKey))
	groth16CudaProvers[dataDir] = p
	debug.FreeOSMemory()
	return p
}

func ProveGroth16(dataDir string, witnessPath string) Proof {
	if dataDir == "" {
		panic("dataDirStr is required")
	}
	os.Setenv("CONSTRAINTS_JSON", dataDir+"/"+constraintsJsonFile)
	os.Setenv("GROTH16", "1")

	groth16CudaMu.Lock()
	defer groth16CudaMu.Unlock()
	// A proof leaves gigabytes of garbage, which Go would otherwise keep until its heap doubles.
	defer func() { go debug.FreeOSMemory() }()
	gpu.TrimPool()
	p := loadGroth16CudaProver(dataDir)

	data, err := os.ReadFile(witnessPath)
	if err != nil {
		panic(err)
	}
	var witnessInput WitnessInput
	if err := json.Unmarshal(data, &witnessInput); err != nil {
		panic(err)
	}
	assignment := NewCircuit(witnessInput)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	bn254Proof, err := p.Prove(witness)
	if err != nil {
		panic(err)
	}
	var proof groth16.Proof = bn254Proof
	return NewSP1Groth16Proof(&proof, witnessInput)
}
