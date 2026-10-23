//go:build cuda

package sp1

import (
	"bufio"
	"encoding/json"
	"os"
	"runtime"
	"runtime/debug"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1/gpu"
)

type plonkCudaProver struct {
	prover *gpu.PlonkProver
	vk     *plonk_bn254.VerifyingKey
}

var (
	plonkCudaMu      sync.Mutex
	plonkCudaProvers = map[string]*plonkCudaProver{}
)

// loadPlonkCudaProver keeps the circuit and its GPU proving key resident for the life of the process.
func loadPlonkCudaProver(dataDir string) *plonkCudaProver {
	if p, ok := plonkCudaProvers[dataDir]; ok {
		return p
	}
	scsFile, err := os.Open(dataDir + "/" + plonkCircuitPath)
	if err != nil {
		panic(err)
	}
	defer scsFile.Close()
	scs := plonk.NewCS(ecc.BN254)
	if _, err := scs.ReadFrom(bufio.NewReaderSize(scsFile, 1024*1024)); err != nil {
		panic(err)
	}

	pkFile, err := os.Open(dataDir + "/" + plonkPkPath)
	if err != nil {
		panic(err)
	}
	defer pkFile.Close()
	vkFile, err := os.Open(dataDir + "/" + plonkVkPath)
	if err != nil {
		panic(err)
	}
	defer vkFile.Close()
	vk := plonk.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(vkFile); err != nil {
		panic(err)
	}

	prover, err := gpu.NewPlonkProver(scs.(*cs.SparseR1CS), bufio.NewReaderSize(pkFile, 1024*1024))
	if err != nil {
		panic(err)
	}
	// A smaller heap leaves huge pages for the solver's random access.
	runtime.GC()
	debug.FreeOSMemory()

	p := &plonkCudaProver{prover: prover, vk: vk.(*plonk_bn254.VerifyingKey)}
	plonkCudaProvers[dataDir] = p
	return p
}

// witnessVector lays out the witness as frontend.NewWitness does for Circuit: the public inputs, then
// Vars, Felts and the limbs of Exts.
func WitnessVector(w WitnessInput) (fr.Vector, error) {
	strs := []string{w.VkeyHash, w.CommittedValuesDigest, w.ExitCode, w.VkRoot, w.ProofNonce}
	strs = append(strs, w.Vars...)
	strs = append(strs, w.Felts...)
	for _, e := range w.Exts {
		strs = append(strs, e...)
	}
	v := make(fr.Vector, len(strs))
	var mu sync.Mutex
	var firstErr error
	var wg sync.WaitGroup
	chunk := (len(strs) + runtime.NumCPU() - 1) / runtime.NumCPU()
	for start := 0; start < len(strs); start += chunk {
		wg.Add(1)
		go func(start int) {
			defer wg.Done()
			for i := start; i < min(len(strs), start+chunk); i++ {
				if _, err := v[i].SetString(strs[i]); err != nil {
					mu.Lock()
					firstErr = err
					mu.Unlock()
				}
			}
		}(start)
	}
	wg.Wait()
	return v, firstErr
}

func ProvePlonk(dataDir string, witnessPath string) Proof {
	if dataDir == "" {
		panic("dataDirStr is required")
	}
	os.Setenv("CONSTRAINTS_JSON", dataDir+"/"+constraintsJsonFile)

	plonkCudaMu.Lock()
	defer plonkCudaMu.Unlock()
	// A proof leaves gigabytes of garbage, which Go would otherwise keep until its heap doubles.
	defer func() { go debug.FreeOSMemory() }()
	gpu.TrimPool()
	p := loadPlonkCudaProver(dataDir)

	data, err := os.ReadFile(witnessPath)
	if err != nil {
		panic(err)
	}
	var witnessInput WitnessInput
	if err := json.Unmarshal(data, &witnessInput); err != nil {
		panic(err)
	}
	witness, err := WitnessVector(witnessInput)
	if err != nil {
		panic(err)
	}

	bn254Proof, err := p.prover.Prove(witness)
	if err != nil {
		panic(err)
	}
	if err := plonk_bn254.Verify(bn254Proof, p.vk, witness[:p.vk.NbPublicVariables]); err != nil {
		panic(err)
	}
	var proof plonk.Proof = bn254Proof
	return NewSP1PlonkBn254Proof(&proof, witnessInput)
}
