package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"

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
func New(ctx context.Context, dataDir, circuitBucket, circuitType, circuitVersion string) (*Server, error) {
	r1cs, pk, vk, err := LoadCircuit(ctx, dataDir, circuitBucket, circuitType, circuitVersion)
	if err != nil {
		return nil, errors.Wrap(err, "loading circuit")
	}
	fmt.Println("Loaded circuit")

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
	router.HandleFunc("POST /groth16/verify", s.handleGroth16Verify)

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
	assignment := sp1.NewCircuitFromWitness(witnessInput)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		ReturnErrorJSON(w, "generating witness", http.StatusInternalServerError)
		return
	}

	// Generate the proof.
	fmt.Println("Generating proof...")
	proof, err := groth16.Prove(s.r1cs, s.pk, witness)
	if err != nil {
		ReturnErrorJSON(w, "generating proof", http.StatusInternalServerError)
		return
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

	ReturnJSON(w, groth16Proof, http.StatusOK)
}

// Function to deserialize SP1.Groth16Proof to Groth16Proof.
func deserializeSP1Groth16Proof(sp1Proof sp1.Groth16Proof) (*groth16.Proof, error) {
	const fpSize = 4 * 8
	proofBytes := make([]byte, 8*fpSize)
	for i, val := range []string{sp1Proof.A[0], sp1Proof.A[1], sp1Proof.B[0][0], sp1Proof.B[0][1], sp1Proof.B[1][0], sp1Proof.B[1][1], sp1Proof.C[0], sp1Proof.C[1]} {
		bigInt, ok := new(big.Int).SetString(val, 10)
		if !ok {
			return nil, fmt.Errorf("invalid big.Int value: %s", val)
		}
		copy(proofBytes[fpSize*i:fpSize*(i+1)], bigInt.Bytes())
	}

	var buf bytes.Buffer
	buf.Write(proofBytes)
	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(&buf); err != nil {
		return nil, fmt.Errorf("reading proof from buffer: %w", err)
	}

	return &proof, nil
}

// handleGroth16Verify accepts a POST request with a JSON body containing the witness and returns a JSON
// body containing the proof using the Groth16 circuit.
func (s *Server) handleGroth16Verify(w http.ResponseWriter, r *http.Request) {
	var verifyInput sp1.VerifierInput
	err := json.NewDecoder(r.Body).Decode(&verifyInput)
	if err != nil {
		ReturnErrorJSON(w, "decoding request", http.StatusBadRequest)
		return
	}

	assignment := sp1.Circuit{
		VkeyHash:             verifyInput.VkeyHash,
		CommitedValuesDigest: verifyInput.CommitedValuesDigest,
	}

	witnessPublic, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		ReturnErrorJSON(w, "getting public witness", http.StatusInternalServerError)
		return
	}

	proof, err := deserializeSP1Groth16Proof(verifyInput.Proof)
	if err != nil {
		ReturnErrorJSON(w, "deserializing proof", http.StatusInternalServerError)
		return
	}

	// Verify the proof.
	err = groth16.Verify(*proof, s.vk, witnessPublic)
	if err != nil {
		ReturnErrorJSON(w, "verifying proof", http.StatusInternalServerError)
		return
	}

	ReturnJSON(w, true, http.StatusOK)
}
