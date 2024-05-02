package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/pkg/errors"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1"
)

type Server struct {
	r1cs constraint.ConstraintSystem
	pk   groth16.ProvingKey
}

// New creates a new server instance with the R1CS and proving key for the given circuit type and
// version.
func New(ctx context.Context, dataDir, circuitType string) (*Server, error) {
	r1cs, pk, err := LoadCircuit(ctx, dataDir, circuitType)
	if err != nil {
		return nil, errors.Wrap(err, "loading circuit")
	}

	s := &Server{
		r1cs: r1cs,
		pk:   pk,
	}
	return s, nil
}

// Start starts listening for requests on the given address.
func (s *Server) Start(port string) {
	router := http.NewServeMux()
	router.HandleFunc("GET /healthz", s.healthz)
	router.HandleFunc("POST /groth16/prove", s.handleGroth16Prove)

	fmt.Printf("Starting server on %s\n", port)
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
	fmt.Println("Generating witness...")
	start := time.Now()
	assignment := sp1.NewCircuitFromWitness(witnessInput)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		ReturnErrorJSON(w, "generating witness", http.StatusInternalServerError)
		return
	}
	fmt.Printf("Witness generated in %s\n", time.Since(start))

	// Generate the proof.
	fmt.Println("Generating proof...")
	start = time.Now()
	proof, err := groth16.Prove(s.r1cs, s.pk, witness)
	if err != nil {
		ReturnErrorJSON(w, "generating proof", http.StatusInternalServerError)
		return
	}
	fmt.Printf("Proof generated in %s\n", time.Since(start))

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

	ReturnJSON(w, groth16Proof, http.StatusOK)
}
