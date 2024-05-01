package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/pkg/errors"
)

// LoadCircuit checks if the necessary circuit files are in the specified data directory,
// downloads them if not, and loads them into memory.
func LoadCircuit(ctx context.Context, dataDir, circuitBucket, circuitType, circuitVersion string) (constraint.ConstraintSystem, groth16.ProvingKey, error) {
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
		fmt.Println("files not found, downloading circuit...")
		// Download artifacts if they don't exist in the dataDir
		if err := DownloadArtifacts(ctx, dataDir, circuitBucket, circuitType, circuitVersion); err != nil {
			return nil, nil, errors.Wrap(err, "downloading artifacts")
		}
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

// DownloadArtifacts downloads and extracts all files from S3 into the specified data directory.
func DownloadArtifacts(ctx context.Context, dataDir, circuitBucket, circuitType, circuitVersion string) error {
	// Ensure data directory exists
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return errors.Wrap(err, "creating data directory")
		}
	}

	awsConfig, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return errors.Wrap(err, "loading AWS config")
	}

	s3Downloader := manager.NewDownloader(s3.NewFromConfig(awsConfig), func(d *manager.Downloader) {
		d.PartSize = 256 * 1024 * 1024 // 256MB per part
		d.Concurrency = 32
	})

	// Create a WriteAtBuffer and wrap it with the ProgressTrackingWriter.
	tarballBuffer := manager.NewWriteAtBuffer(nil)
	progressWriter := NewProgressTrackingWriter(tarballBuffer)

	_, err = s3Downloader.Download(ctx, progressWriter, &s3.GetObjectInput{
		Bucket: aws.String(circuitBucket),
		Key:    aws.String(fmt.Sprintf("%s-build%s.tar.gz", circuitType, circuitVersion)),
	})
	if err != nil {
		return errors.Wrap(err, "downloading circuit")
	}

	// Retrieve the total bytes downloaded.
	totalBytes := atomic.LoadInt64(&progressWriter.totalBytes)
	fmt.Printf("Downloaded circuit tarball (%d bytes)\n", totalBytes)

	gzipReader, err := gzip.NewReader(bytes.NewReader(tarballBuffer.Bytes()))
	if err != nil {
		return errors.Wrap(err, "decompressing gzip")
	}

	tarReader := tar.NewReader(gzipReader)

	// Ensure that the data directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return errors.Wrap(err, "creating data directory")
	}

	// Extract all files from the tarball
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "reading tarball")
		}

		// Normalize the file path to avoid relative path issues
		cleanHeaderName := filepath.Clean(header.Name)

		// Skip invalid or AppleDouble files
		if cleanHeaderName == "" || strings.HasPrefix(cleanHeaderName, "._") || strings.Contains(cleanHeaderName, "..") {
			continue
		}

		// Construct the full file path
		filePath := filepath.Join(dataDir, cleanHeaderName)

		// Skip if the path already exists and is a directory
		if info, err := os.Stat(filePath); err == nil && info.IsDir() {
			continue
		}

		// Create the file and write its content
		file, err := os.Create(filePath)
		if err != nil {
			return errors.Wrap(err, "creating file")
		}
		defer file.Close()

		if _, err = io.Copy(file, tarReader); err != nil {
			return errors.Wrap(err, "copying file content")
		}
	}

	return nil
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
