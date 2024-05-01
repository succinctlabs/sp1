package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/pkg/errors"
)

// LoadCircuit checks if the necessary circuit files are in the specified data directory,
// downloads them if not, and loads them into memory.
func LoadCircuit(ctx context.Context, dataDir, circuitType string) (constraint.ConstraintSystem, groth16.ProvingKey, error) {
	r1csPath := filepath.Join(dataDir, "circuit_"+circuitType+".bin")
	pkPath := filepath.Join(dataDir, "pk_"+circuitType+".bin")

	// Ensure data directory exists
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return nil, nil, errors.Wrap(err, "creating data directory")
		}
	}

	// Check if the R1CS and Proving Key files exist in the data directory.
	filesExist := fileExists(r1csPath) && fileExists(pkPath)

	if !filesExist {
		return nil, nil, errors.New("circuit files not found")
	} else {
		fmt.Println("files found, loading circuit...")
	}

	// Load the circuit artifacts into memory
	r1cs, pk, err := LoadCircuitArtifacts(dataDir, circuitType)
	if err != nil {
		return nil, nil, errors.Wrap(err, "loading circuit artifacts")
	}

	return r1cs, pk, nil
}

// LoadCircuitArtifacts loads the R1CS and Proving Key from the specified data directory into memory.
func LoadCircuitArtifacts(dataDir, circuitType string) (constraint.ConstraintSystem, groth16.ProvingKey, error) {
	r1csFilePath := filepath.Join(dataDir, "circuit_"+circuitType+".bin")
	pkFilePath := filepath.Join(dataDir, "pk_"+circuitType+".bin")

	// Read the R1CS content
	r1csFile, err := os.Open(r1csFilePath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "opening R1CS file")
	}

	r1csFile.Seek(0, io.SeekStart)
	r1csContent, err := io.ReadAll(r1csFile)
	if err != nil {
		return nil, nil, errors.Wrap(err, "reading R1CS content")
	}

	// Read the PK content
	pkFile, err := os.Open(pkFilePath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "opening PK file")
	}

	pkFile.Seek(0, io.SeekStart)
	pkContent, err := io.ReadAll(pkFile)
	if err != nil {
		return nil, nil, errors.Wrap(err, "reading PK content")
	}

	// Load R1CS and Proving Key into memory
	r1cs := groth16.NewCS(ecc.BN254)
	_, err = r1cs.ReadFrom(bytes.NewReader(r1csContent))
	if err != nil {
		return nil, nil, errors.Wrap(err, "error reading R1CS content")
	}

	pk := groth16.NewProvingKey(ecc.BN254)
	_, err = pk.ReadFrom(bytes.NewReader(pkContent))
	if err != nil {
		return nil, nil, errors.Wrap(err, "error reading PK content")
	}

	return r1cs, pk, nil
}

// Helper function to check if a file exists.
func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return !os.IsNotExist(err)
}

// ProgressTrackingWriter wraps a `WriterAt` to track progress.
type ProgressTrackingWriter struct {
	underlying io.WriterAt
	totalBytes int64
}

func (ptw *ProgressTrackingWriter) WriteAt(p []byte, offset int64) (int, error) {
	n, err := ptw.underlying.WriteAt(p, offset)
	atomic.AddInt64(&ptw.totalBytes, int64(n))
	if os.Getenv("VERBOSE") == "true" {
		offsetGB := bytesToGigabytes(offset)
		fmt.Printf("Downloaded %.6f GB\n", offsetGB)
	}
	return n, err
}

func bytesToGigabytes(bytes int64) float64 {
	const bytesPerGigabyte = 1024 * 1024 * 1024
	return float64(bytes) / float64(bytesPerGigabyte)
}

// Creates a new `ProgressTrackingWriter` given an underlying `WriterAt`.
func NewProgressTrackingWriter(writer io.WriterAt) *ProgressTrackingWriter {
	return &ProgressTrackingWriter{
		underlying: writer,
		totalBytes: 0,
	}
}
