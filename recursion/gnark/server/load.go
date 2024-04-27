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

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/pkg/errors"
)

// LoadCircuit checks if the necessary files exist in the data directory, and if not, downloads them.
func LoadCircuit(ctx context.Context, dataDir, circuitBucket, circuitType, circuitVersion string) (constraint.ConstraintSystem, groth16.ProvingKey, error) {
	r1csPath := filepath.Join(dataDir, "circuit_"+circuitType+".bin")
	pkPath := filepath.Join(dataDir, "pk_"+circuitType+".bin")

	// Ensure data directory exists, create if necessary.
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return nil, nil, errors.Wrap(err, "creating data directory")
		}
	}

	// Check if the R1CS and proving key files exist in the data directory.
	filesExist := fileExists(r1csPath) && fileExists(pkPath)

	var r1cs constraint.ConstraintSystem
	var pk groth16.ProvingKey
	var err error

	if !filesExist {
		// If files do not exist, download them from the S3 bucket.
		fmt.Printf("Files not found in data dir, downloading from bucket %s...\n", circuitBucket)
		r1cs, pk, err = downloadCircuit(ctx, dataDir, circuitBucket, circuitType, circuitVersion)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to download circuit")
		}
	} else {
		fmt.Printf("Files found in data dir. Loading from %s...\n", dataDir)
	}

	return r1cs, pk, nil
}

// DownloadCircuit downloads the R1CS and proving key and loads them into memory.
// TODO: split this function into two functions, one for downloading and one for loading.
func downloadCircuit(ctx context.Context, dataDir, circuitBucket, circuitType, circuitVersion string) (constraint.ConstraintSystem, groth16.ProvingKey, error) {
	// Setup AWS S3 downloader.
	awsConfig, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, nil, errors.Wrap(err, "loading AWS config")
	}
	s3Downloader := manager.NewDownloader(s3.NewFromConfig(awsConfig), func(d *manager.Downloader) {
		d.PartSize = 128 * 1024 * 1024 // 128MB per part
		d.Concurrency = 32
	})

	// Download the circuit tarball
	tarballBuffer := manager.NewWriteAtBuffer(nil)
	_, err = s3Downloader.Download(ctx, tarballBuffer, &s3.GetObjectInput{
		Bucket: aws.String(circuitBucket),
		Key:    aws.String(fmt.Sprintf("%s-build%s.tar.gz", circuitType, circuitVersion)),
	})
	if err != nil {
		return nil, nil, errors.Wrap(err, "downloading circuit")
	}
	tarballSize := len(tarballBuffer.Bytes())
	if tarballSize == 0 {
		return nil, nil, errors.New("downloaded tarball is empty")
	}
	fmt.Printf("Downloaded circuit tarball (%d bytes)\n", tarballSize)

	gzipReader, err := gzip.NewReader(bytes.NewReader(tarballBuffer.Bytes()))
	if err != nil {
		return nil, nil, errors.Wrap(err, "error decompressing gzip")
	}

	tarReader := tar.NewReader(gzipReader)

	// Create file paths in dataDir
	r1csFilePath := fmt.Sprintf("build/circuit_%s.bin", circuitType)
	pkFilePath := fmt.Sprintf("build/pk_%s.bin", circuitType)

	// Create files in dataDir
	r1csFile, err := os.Create(r1csFilePath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating R1CS file")
	}
	defer os.Remove(r1csFilePath)

	pkFile, err := os.Create(pkFilePath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating PK file")
	}
	defer os.Remove(pkFilePath)

	// Extract files from tarball and write to dataDir
	var r1csExtracted, pkExtracted bool
	for {
		if r1csExtracted && pkExtracted {
			break
		}

		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, nil, errors.Wrap(err, "error reading tarball")
		}

		fileName := strings.ToLower(header.Name)

		switch {
		case strings.EqualFold(fileName, r1csFilePath):
			_, err = io.Copy(r1csFile, tarReader)
			if err != nil {
				return nil, nil, errors.Wrap(err, "copying R1CS content")
			}
			r1csFile.Seek(0, io.SeekStart)
			r1csExtracted = true

		case strings.EqualFold(fileName, pkFilePath):
			_, err = io.Copy(pkFile, tarReader)
			if err != nil {
				return nil, nil, errors.Wrap(err, "copying PK content")
			}
			pkFile.Seek(0, io.SeekStart)
			pkExtracted = true
		}
	}

	if !r1csExtracted {
		return nil, nil, errors.New("R1CS file not extracted")
	}
	if !pkExtracted {
		return nil, nil, errors.New("PK file not extracted")
	}

	// Read the content from dataDir
	r1csFile.Seek(0, io.SeekStart)
	r1csContent, err := io.ReadAll(r1csFile)
	if err != nil {
		return nil, nil, errors.Wrap(err, "reading R1CS content")
	}

	pkFile.Seek(0, io.SeekStart)
	pkContent, err := io.ReadAll(pkFile)
	if err != nil {
		return nil, nil, errors.Wrap(err, "reading PK content")
	}

	// Load R1CS and PK into memory
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
