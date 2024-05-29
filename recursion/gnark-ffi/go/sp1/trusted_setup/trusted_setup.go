package trusted_setup

import (
	"log"
	"os"

	stdbits "math/bits"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark-ignition-verifier/ignition"
	"github.com/consensys/gnark/constraint"
)

func sanityCheck(srs *kzg_bn254.SRS) {
	// we can now use the SRS to verify a proof
	// create a polynomial
	f := randomPolynomial(60)

	// commit the polynomial
	digest, err := kzg_bn254.Commit(f, srs.Pk)
	if err != nil {
		log.Fatal(err)
	}

	// compute opening proof at a random point
	var point fr.Element
	point.SetString("4321")
	proof, err := kzg_bn254.Open(f, point, srs.Pk)
	if err != nil {
		log.Fatal(err)
	}

	// verify the claimed valued
	expected := eval(f, point)
	if !proof.ClaimedValue.Equal(&expected) {
		log.Fatal("inconsistent claimed value")
	}

	// verify correct proof
	err = kzg_bn254.Verify(&digest, &proof, point, srs.Vk)
	if err != nil {
		log.Fatal(err)
	}
}

func randomPolynomial(size int) []fr.Element {
	f := make([]fr.Element, size)
	for i := 0; i < size; i++ {
		f[i].SetRandom()
	}
	return f
}

// eval returns p(point) where p is interpreted as a polynomial
// ∑_{i<len(p)}p[i]Xⁱ
func eval(p []fr.Element, point fr.Element) fr.Element {
	var res fr.Element
	n := len(p)
	res.Set(&p[n-1])
	for i := n - 2; i >= 0; i-- {
		res.Mul(&res, &point).Add(&res, &p[i])
	}
	return res
}

func DownloadAndSaveAztecIgnitionSrs(startIdx int, fileName string) {
	config := ignition.Config{
		BaseURL:  "https://aztec-ignition.s3.amazonaws.com/",
		Ceremony: "MAIN IGNITION", // "TINY_TEST_5"
		CacheDir: "./data",
	}

	if config.CacheDir != "" {
		err := os.MkdirAll(config.CacheDir, os.ModePerm)

		if err != nil {
			log.Fatal("when creating cache dir: ", err)
			panic(err)
		}
	}

	log.Println("fetch manifest")

	manifest, err := ignition.NewManifest(config)

	if err != nil {
		log.Fatal("when fetching manifest: ", err)
	}

	current, next := ignition.NewContribution(manifest.NumG1Points), ignition.NewContribution(manifest.NumG1Points)

	if err := current.Get(manifest.Participants[startIdx], config); err != nil {
		log.Fatal("when fetching contribution: ", err)
	}
	if err := next.Get(manifest.Participants[startIdx+1], config); err != nil {
		log.Fatal("when fetching contribution: ", err)
	}
	if !next.Follows(&current) {
		log.Fatalf("contribution %d does not follow contribution %d", startIdx+1, startIdx)
	}

	for i := startIdx + 2; i < len(manifest.Participants); i++ {
		log.Println("processing contribution ", i+1)
		current, next = next, current
		if err := next.Get(manifest.Participants[i], config); err != nil {
			log.Fatal("when fetching contribution ", i+1, ": ", err)
		}
		if !next.Follows(&current) {
			log.Fatal("contribution ", i+1, " does not follow contribution ", i, ": ", err)
		}
	}

	log.Println("success ✅: all contributions are valid")

	_, _, _, g2gen := bn254.Generators()
	// we use the last contribution to build a kzg SRS for bn254
	srs := kzg_bn254.SRS{
		Pk: kzg_bn254.ProvingKey{
			G1: next.G1,
		},
		Vk: kzg_bn254.VerifyingKey{
			G1: next.G1[0],
			G2: [2]bn254.G2Affine{
				g2gen,
				next.G2[0],
			},
		},
	}

	// sanity check
	sanityCheck(&srs)
	log.Println("success ✅: kzg sanity check with SRS")

	fSRS, err := os.Create(fileName)
	if err != nil {
		log.Fatal("error creating srs file: ", err)
		panic(err)
	}
	defer fSRS.Close()

	_, err = srs.WriteTo(fSRS)
	if err != nil {
		log.Fatal("error writing srs file: ", err)
		panic(err)
	}
}

func ToLagrange(scs constraint.ConstraintSystem, canonicalSRS kzg.SRS) kzg.SRS {
	var lagrangeSRS kzg.SRS

	switch srs := canonicalSRS.(type) {
	case *kzg_bn254.SRS:
		var err error
		sizeSystem := scs.GetNbPublicVariables() + scs.GetNbConstraints()
		nextPowerTwo := 1 << stdbits.Len(uint(sizeSystem))
		newSRS := &kzg_bn254.SRS{Vk: srs.Vk}
		newSRS.Pk.G1, err = kzg_bn254.ToLagrangeG1(srs.Pk.G1[:nextPowerTwo])
		if err != nil {
			panic(err)
		}
		lagrangeSRS = newSRS
	default:
		panic("unrecognized curve")
	}

	return lagrangeSRS
}
