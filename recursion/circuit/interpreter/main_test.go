package main

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
)

func TestMain(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit Circuit
	assert.ProverSucceeded(&circuit, &Circuit{
		X: 0,
		Y: 0,
	}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}
