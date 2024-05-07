package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/pkg/errors"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1"
)

type Server struct {
	scs constraint.ConstraintSystem
	pk  plonk.ProvingKey
	vk  plonk.VerifyingKey
}

// New creates a new server instance with the R1CS and proving key for the given circuit type and
// version.
func New(ctx context.Context, dataDir, circuitType string) (*Server, error) {
	scs, pk, vk, err := LoadCircuit(ctx, dataDir, circuitType)
	if err != nil {
		return nil, errors.Wrap(err, "loading circuit")
	}

	s := &Server{
		scs: scs,
		pk:  pk,
		vk:  vk,
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
	if s.scs == nil || s.pk == nil {
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

	fmt.Println("assignment:", assignment)
	fmt.Println("PublicInputs: VkeyHash", witnessInput.VkeyHash)
	fmt.Println("PublicInputs: CommitedValuesDigest", witnessInput.CommitedValuesDigest)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		ReturnErrorJSON(w, "generating witness", http.StatusInternalServerError)
		return
	}
	fmt.Printf("Witness generated in %s\n", time.Since(start))

	// Generate the proof.
	fmt.Println("Generating proof...")
	start = time.Now()
	proof, err := plonk.Prove(s.scs, s.pk, witness)
	if err != nil {
		ReturnErrorJSON(w, "generating proof", http.StatusInternalServerError)
		return
	}
	fmt.Printf("Proof generated in %s\n", time.Since(start))

	// Verify the proof.
	witnessPublic, err := witness.Public()
	if err != nil {
		ReturnErrorJSON(w, "getting witness public", http.StatusInternalServerError)
		return
	}
	fmt.Println("Verifying proof")
	err = plonk.Verify(proof, s.vk, witnessPublic)
	if err != nil {
		ReturnErrorJSON(w, "verifying proof", http.StatusInternalServerError)
		return
	}
	fmt.Println(witnessPublic)
	fmt.Println(witnessPublic.Vector())

	_proof, ok := proof.(interface{ MarshalSolidity() []byte })
	if !ok {
		panic("proof does not implement MarshalSolidity()")
	}
	proofBytes := _proof.MarshalSolidity()
	proofStr := hex.EncodeToString(proofBytes)
	var publicInputs [2]string
	publicInputs[0] = witnessInput.VkeyHash
	publicInputs[1] = witnessInput.CommitedValuesDigest

	encodedProof := sp1.PlonkProof{
		EncodedProof: proofStr,
		PublicInputs: publicInputs,
	}

	ReturnJSON(w, encodedProof, http.StatusOK)

}
