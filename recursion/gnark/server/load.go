package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
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

// LoadCircuit downloads the R1CS and proving key and loads it into memory.
func LoadCircuit(ctx context.Context, circuitBucket, circuitType, circuitVersion string) (constraint.ConstraintSystem, groth16.ProvingKey, error) {
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

	// Decompress the gzip tarball.
	gzipReader, err := gzip.NewReader(bytes.NewReader(tarballBuffer.Bytes()))
	if err != nil {
		return nil, nil, errors.Wrap(err, "error decompressing gzip")
	}

	// Read the tarball.
	tarReader := tar.NewReader(gzipReader)

	// Temporary files to write and read to.
	r1csTempFile, err := os.CreateTemp("", "r1cs")
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating temp file for r1cs")
	}
	defer os.Remove(r1csTempFile.Name())
	pkTimeFile, err := os.CreateTemp("", "pk")
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating temp file for proving key")
	}
	defer os.Remove(r1csTempFile.Name())

	r1csFileName := fmt.Sprintf("build/circuit_%s.bin", circuitType)
	pkFileName := fmt.Sprintf("build/pk_%s.bin", circuitType)

	var r1csExtracted, pkExtracted bool
	for {
		if r1csExtracted && pkExtracted {
			break
		}

		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, nil, errors.Wrap(err, "reading tarball")
		}
		fileName := strings.ToLower(header.Name)

		switch {
		case strings.EqualFold(fileName, r1csFileName):
			_, err = io.Copy(r1csTempFile, tarReader)
			if err != nil {
				return nil, nil, errors.Wrap(err, "copying r1cs to temp file")
			}
			r1csTempFile.Seek(0, io.SeekStart)
			r1csExtracted = true

		case strings.EqualFold(fileName, pkFileName):
			_, err = io.Copy(pkTimeFile, tarReader)
			if err != nil {
				return nil, nil, errors.Wrap(err, "copying pk to temp file")
			}
			pkTimeFile.Seek(0, io.SeekStart)
			pkExtracted = true
		}
	}

	if !r1csExtracted {
		return nil, nil, errors.New("r1cs file not extracted")
	}
	if !pkExtracted {
		return nil, nil, errors.New("pk file not extracted")
	}

	r1csTempFile.Seek(0, io.SeekStart)
	r1csContent, err := io.ReadAll(r1csTempFile)
	if err != nil {
		return nil, nil, errors.Wrap(err, "reading r1cs content")
	}

	pkTimeFile.Seek(0, io.SeekStart)
	pkContent, err := io.ReadAll(pkTimeFile)
	if err != nil {
		return nil, nil, errors.Wrap(err, "reading pk content")
	}

	// Load the r1cs and pk into memory.
	r1cs := groth16.NewCS(ecc.BN254)
	r1cs.ReadFrom(bytes.NewReader(r1csContent))
	pk := groth16.NewProvingKey(ecc.BN254)
	pk.ReadFrom(bytes.NewReader(pkContent))

	return r1cs, pk, nil
}


func 