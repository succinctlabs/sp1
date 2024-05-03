package server

import (
	"context"
	"encoding/json"
	"fmt"
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
	groth16Proof, err := sp1.SerializeGnarkGroth16Proof(&proof, witnessInput)
	if err != nil {
		ReturnErrorJSON(w, "serializing proof", http.StatusInternalServerError)
		return
	}

	ReturnJSON(w, groth16Proof, http.StatusOK)
}
