package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/pkg/errors"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
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
	proof, err := groth16.Prove(s.r1cs, s.pk, witness, backend.WithProverChallengeHashFunction(sha256.New()))
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
	err = groth16.Verify(proof, s.vk, witnessPublic)
	if err != nil {
		ReturnErrorJSON(w, "verifying proof", http.StatusInternalServerError)
		return
	}

	_proof, ok := proof.(interface{ MarshalSolidity() []byte })
	if !ok {
		panic("proof does not implement MarshalSolidity()")
	}
	proofBytes := _proof.MarshalSolidity()
	proofStr := hex.EncodeToString(proofBytes)
	fmt.Println("x Proof:", proofStr)
	bPublicWitness, err := witness.MarshalBinary()
	if err == nil {
		panic("public witness does not implement MarshalBinary()")
	}
	bPublicWitness = bPublicWitness[12:]
	publicWitnessStr := hex.EncodeToString(bPublicWitness)
	fmt.Println("x PublicWitness:", publicWitnessStr)

	// Serialize the proof to JSON.
	groth16Proof, err := sp1.SerializeGnarkGroth16Proof(&proof, witnessInput)
	if err != nil {
		ReturnErrorJSON(w, "serializing proof", http.StatusInternalServerError)
		return
	}

	// convert public inputs
	nbInputs := len(bPublicWitness) / fr.Bytes
	if nbInputs != 2 {
		panic("nbInputs != nbPublicInputs")
	}
	var input [2]*big.Int
	for i := 0; i < nbInputs; i++ {
		var e fr.Element
		e.SetBytes(bPublicWitness[fr.Bytes*i : fr.Bytes*(i+1)])
		input[i] = new(big.Int)
		e.BigInt(input[i])
	}
	fmt.Println("x input:", input)

	fpSize := 4 * 8

	// solidity contract inputs
	var proofF [8]*big.Int

	// proof.Ar, proof.Bs, proof.Krs
	for i := 0; i < 8; i++ {
		proofF[i] = new(big.Int).SetBytes(proofBytes[fpSize*i : fpSize*(i+1)])
	}

	fmt.Println("x ProofF:", proofF)

	// prepare commitments for calling
	c := new(big.Int).SetBytes(proofBytes[fpSize*8 : fpSize*8+4])
	commitmentCount := int(c.Int64())

	var commitments [2]*big.Int
	var commitmentPok [2]*big.Int

	for i := 0; i < 2*commitmentCount; i++ {
		commitments[i] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+i*fpSize : fpSize*8+4+(i+1)*fpSize])
	}

	commitmentPok[0] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize : fpSize*8+4+2*commitmentCount*fpSize+fpSize])
	commitmentPok[1] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize+fpSize : fpSize*8+4+2*commitmentCount*fpSize+2*fpSize])

	fmt.Println("x commitments:", commitments)
	fmt.Println("x commitmentPok:", commitmentPok)

	ReturnJSON(w, groth16Proof, http.StatusOK)
}
