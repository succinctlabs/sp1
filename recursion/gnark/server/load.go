package server

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

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
		fmt.Println("Files found, loading circuit...")
	}

	// Load the circuit artifacts into memory
	r1cs, pk, err := LoadCircuitArtifacts(dataDir, circuitType)
	if err != nil {
		return nil, nil, errors.Wrap(err, "loading circuit artifacts")
	}
	fmt.Println("Circuit artifacts loaded successfully")

	return r1cs, pk, nil
}

// LoadCircuitArtifacts loads the R1CS and Proving Key from the specified data directory into memory.
func LoadCircuitArtifacts(dataDir, circuitType string) (constraint.ConstraintSystem, groth16.ProvingKey, error) {
	var wg sync.WaitGroup
	var r1cs constraint.ConstraintSystem
	var pk groth16.ProvingKey
	var errR1CS, errPK error

	startTime := time.Now()
	fmt.Printf("Loading artifacts start time %s\n", startTime.Format(time.RFC3339))

	wg.Add(2)
	go func() {
		defer wg.Done()

		r1csFilePath := filepath.Join(dataDir, "circuit_"+circuitType+".bin")
		fmt.Println("Opening R1CS file at:", r1csFilePath)
		r1csFile, err := os.Open(r1csFilePath)
		if err != nil {
			errR1CS = errors.Wrap(err, "opening R1CS file")
			return
		}
		defer r1csFile.Close()

		r1csReader := bufio.NewReader(r1csFile)
		r1csStart := time.Now()
		r1cs = groth16.NewCS(ecc.BN254)
		fmt.Println("Reading R1CS file...")
		if _, err = r1cs.ReadFrom(r1csReader); err != nil {
			errR1CS = errors.Wrap(err, "reading R1CS content from file")
		} else {
			fmt.Printf("R1CS loaded in %s\n", time.Since(r1csStart))
		}
	}()

	go func() {
		defer wg.Done()

		pkFilePath := filepath.Join(dataDir, "pk_"+circuitType+".bin")
		fmt.Println("Opening PK file at:", pkFilePath)
		pkFile, err := os.Open(pkFilePath)
		if err != nil {
			errPK = errors.Wrap(err, "opening PK file")
			return
		}
		defer pkFile.Close()

		pkReader := bufio.NewReader(pkFile)
		pkStart := time.Now()
		pk = groth16.NewProvingKey(ecc.BN254)
		fmt.Println("Reading PK file...")
		if _, err = pk.UnsafeReadFrom(pkReader); err != nil {
			errPK = errors.Wrap(err, "reading PK content from file")
		} else {
			fmt.Printf("PK loaded in %s\n", time.Since(pkStart))
		}
	}()

	wg.Wait()

	if errR1CS != nil {
		return nil, nil, errors.Wrap(errR1CS, "processing R1CS")
	}
	if errPK != nil {
		return nil, nil, errors.Wrap(errPK, "processing PK")
	}

	fmt.Printf("Circuit artifacts loaded successfully in %s\n", time.Since(startTime))

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
