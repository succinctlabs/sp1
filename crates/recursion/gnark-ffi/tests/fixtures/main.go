// Generates small proofs with the same public-input layout as the SP1 gnark wrapper.
// These fixtures test verification policy, not the SP1 circuit.
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

type Circuit struct {
	VkeyHash frontend.Variable `gnark:",public"`
	Digest   frontend.Variable `gnark:",public"`
	ExitCode frontend.Variable `gnark:",public"`
	VkRoot   frontend.Variable `gnark:",public"`
	Nonce    frontend.Variable `gnark:",public"`
	ExitCopy frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.VkeyHash, 11)
	api.AssertIsEqual(c.Digest, 22)
	api.AssertIsEqual(c.VkRoot, 33)
	api.AssertIsEqual(c.Nonce, 44)
	api.AssertIsEqual(c.ExitCode, c.ExitCopy)
	return nil
}
func check(err error) {
	if err != nil {
		panic(err)
	}
}
func write(path string, x io.WriterTo, encoded bool) {
	var b bytes.Buffer
	_, err := x.WriteTo(&b)
	check(err)
	data := b.Bytes()
	if encoded {
		data = []byte(hex.EncodeToString(data))
	}
	check(os.WriteFile(path, data, 0600))
}
func main() {
	dir := os.Args[1]
	for _, system := range []string{"groth16", "plonk"} {
		var builder frontend.NewBuilder = r1cs.NewBuilder
		if system == "plonk" {
			builder = scs.NewBuilder
		}
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &Circuit{})
		check(err)
		if system == "groth16" {
			pk, vk, err := groth16.Setup(ccs)
			check(err)
			write(dir+"/groth16_vk.bin", vk, false)
			for _, exit := range []int{0, 1, 3} {
				w, err := frontend.NewWitness(&Circuit{11, 22, exit, 33, 44, exit}, ecc.BN254.ScalarField())
				check(err)
				p, err := groth16.Prove(ccs, pk, w)
				check(err)
				pub, err := w.Public()
				check(err)
				check(groth16.Verify(p, vk, pub))
				write(fmt.Sprintf("%s/groth16-%d.proof", dir, exit), p, true)
			}
		} else {
			srs, lag, err := unsafekzg.NewSRS(ccs)
			check(err)
			pk, vk, err := plonk.Setup(ccs, srs, lag)
			check(err)
			write(dir+"/plonk_vk.bin", vk, false)
			for _, exit := range []int{0, 1, 3} {
				w, err := frontend.NewWitness(&Circuit{11, 22, exit, 33, 44, exit}, ecc.BN254.ScalarField())
				check(err)
				p, err := plonk.Prove(ccs, pk, w)
				check(err)
				pub, err := w.Public()
				check(err)
				check(plonk.Verify(p, vk, pub))
				write(fmt.Sprintf("%s/plonk-%d.proof", dir, exit), p, true)
			}
		}
	}
}
