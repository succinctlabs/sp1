package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

type Server struct {
	r1cs constraint.ConstraintSystem
	pk   groth16.ProvingKey
	vk   groth16.VerifyingKey
}

// New creates a new server instance with the R1CS and proving key for the given circuit type and
// version.
func New(ctx context.Context, dataDir, circuitType string) (*Server, error) {
	r1cs, pk, vk, err := LoadCircuit(ctx, dataDir, circuitType)
	if err != nil {
		return nil, errors.Wrap(err, "loading circuit")
	}

	s := &Server{
		r1cs: r1cs,
		pk:   pk,
		vk:   vk,
	}
	return s, nil
}

// Start starts listening for requests on the given address.
func (s *Server) Start(port string) {
	router := http.NewServeMux()
	router.HandleFunc("GET /healthz", s.healthz)
	router.HandleFunc("POST /groth16/prove", s.handleGroth16Prove)

	fmt.Printf("[sp1] starting server on %s\n", port)
	http.ListenAndServe(":"+port, router)
}

// healthz returns success if the server has the R1CS and proving key loaded. Otherwise, it returns
// an error.
func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	if s.r1cs == nil || s.pk == nil {
		ReturnErrorJSON(w, "not ready", http.StatusInternalServerError)
		return
	}
	ReturnJSON(w, "OK", http.StatusOK)
}

// handleGroth16Prove accepts a POST request with a JSON body containing the witness and returns a JSON
// body containing the proof using the Groth16 circuit.
func (s *Server) handleGroth16Prove(w http.ResponseWriter, r *http.Request) {
	var witnessInput sp1.WitnessInput
	err := json.NewDecoder(r.Body).Decode(&witnessInput)
	if err != nil {
		ReturnErrorJSON(w, "decoding request", http.StatusBadRequest)
		return
	}

	// Generate the witness.
	fmt.Println("[sp1] generating witness...")
	start := time.Now()
	assignment := sp1.NewCircuitFromWitness(witnessInput)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		ReturnErrorJSON(w, "generating witness", http.StatusInternalServerError)
		return
	}
	fmt.Printf("[sp1] witness generated in %s\n", time.Since(start))

	// Generate the proof.
	fmt.Println("[sp1] generating proof...")
	start = time.Now()
	proof, err := groth16.Prove(s.r1cs, s.pk, witness, backend.WithProverHashToFieldFunction(sha256.New()))
	if err != nil {
		ReturnErrorJSON(w, "generating proof", http.StatusInternalServerError)
		return
	}
	fmt.Printf("[sp1] proof generated in %s\n", time.Since(start))

	// Verify the proof.
	witnessPublic, err := witness.Public()
	if err != nil {
		ReturnErrorJSON(w, "getting witness public", http.StatusInternalServerError)
		return
	}
	fmt.Println("[sp1] verifying proof")
	err = groth16.Verify(proof, s.vk, witnessPublic, backend.WithVerifierHashToFieldFunction(sha256.New()))
	if err != nil {
		ReturnErrorJSON(w, "verifying proof", http.StatusInternalServerError)
		return
	}

	// Serialize the proof to JSON.
	groth16Proof, err := sp1.SerializeGnarkGroth16Proof(&proof, witnessInput)
	if err != nil {
		ReturnErrorJSON(w, "serializing proof", http.StatusInternalServerError)
		return
	}

	ReturnJSON(w, groth16Proof, http.StatusOK)
}

func PrintProof(witness witness.Witness, proof groth16.Proof, vk groth16.VerifyingKey) {
	const fpSize = 4 * 8
	var buf = new(bytes.Buffer)
	proof.WriteRawTo(buf)
	proofBytes := buf.Bytes()
	proofs := make([]string, 8)
	for i := 0; i < 8; i++ {
		proofs[i] = "0x" + hex.EncodeToString(proofBytes[i*fpSize:(i+1)*fpSize])
	}
	publicWitness, _ := witness.Public()
	fmt.Println("Public Witness:", publicWitness.Vector())
	commitmentCountBigInt := new(big.Int).SetBytes(proofBytes[fpSize*8 : fpSize*8+4])
	commitmentCount := int(commitmentCountBigInt.Int64())
	var commitments []*big.Int = make([]*big.Int, 2*commitmentCount)
	var commitmentPok [2]*big.Int
	for i := 0; i < 2*commitmentCount; i++ {
		commitments[i] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+i*fpSize : fpSize*8+4+(i+1)*fpSize])
	}
	commitmentPok[0] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize : fpSize*8+4+2*commitmentCount*fpSize+fpSize])
	commitmentPok[1] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize+fpSize : fpSize*8+4+2*commitmentCount*fpSize+2*fpSize])

	fmt.Println("Generating Fixture")
	fmt.Println("uint256[8] memory proofs = [")
	for i := 0; i < 8; i++ {
		fmt.Print(proofs[i])
		if i != 7 {
			fmt.Println(",")
		}
	}
	fmt.Println("];")
	fmt.Println()
	fmt.Println("uint256[2] memory commitments = [")
	for i := 0; i < 2*commitmentCount; i++ {
		fmt.Print(commitments[i])
		if i != 2*commitmentCount-1 {
			fmt.Println(",")
		}
	}
	fmt.Println("];")
	fmt.Println("uint256[2] memory commitmentPok = [")
	for i := 0; i < 2; i++ {
		fmt.Print(commitmentPok[i])
		if i != 1 {
			fmt.Println(",")
		}
	}
	fmt.Println("];")
	fmt.Println()
	fmt.Println("uint256[3] memory inputs = [")
	fmt.Println("uint256(1),")
	fmt.Println("uint256(2),")
	fmt.Println("uint256(3)")
	fmt.Println("];")

	buf = new(bytes.Buffer)
	err := vk.ExportSolidity(buf)
	if err != nil {
		panic(err)
	}
	content := buf.String()

	dirPath := "contracts/src"
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		panic(err)
	}

	contractFile, err := os.Create(dirPath + "/VerifierGroth16.sol")
	if err != nil {
		panic(err)
	}
	defer contractFile.Close()

	w := bufio.NewWriter(contractFile)
	_, err = w.Write([]byte(content))
	if err != nil {
		panic(err)
	}
	err = w.Flush()
	if err != nil {
		panic(err)
	}
}
