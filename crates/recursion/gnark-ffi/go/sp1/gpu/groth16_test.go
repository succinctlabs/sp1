//go:build cuda

package gpu

import (
	"encoding/binary"
	"io"
	"os"
	"testing"
	"unsafe"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
)

func TestNativeKeyTableRange(t *testing.T) {
	const size = 64 << 20
	file, err := os.CreateTemp(t.TempDir(), "points")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	count := size / int(unsafe.Sizeof(curve.G1Affine{}))
	var header [8]byte
	binary.LittleEndian.PutUint64(header[:], uint64(count))
	if _, err := file.Write(header[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte{0x91}); err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(size + 8); err != nil {
		t.Fatal(err)
	}
	pk := &groth16_bn254.ProvingKey{InfinityB: []bool{}}
	r := &dumpReader{
		source: io.NewSectionReader(file, 0, size+8), pk: pk, tables: make(map[*byte]*io.SectionReader),
	}
	if _, err := io.ReadFull(r, header[:]); err != nil {
		t.Fatal(err)
	}
	points := make([]curve.G1Affine, count)
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&points[0])), size)
	if _, err := io.ReadFull(r, buf); err != nil || buf[0] != 0 {
		t.Fatalf("native table was copied into the Go heap, first byte %x, error %v", buf[0], err)
	}

	// A different table sharing the first point must never claim the range.
	short := points[:count-1]
	if takeDumpTable(r, &short) != nil || len(r.tables) != 1 {
		t.Fatal("accepted an affine table with the wrong length")
	}
	section := takeDumpTable(r, &points)
	if section == nil || section.Size() != size || points != nil || len(r.tables) != 0 {
		t.Fatal("the decoder destination did not match its file range")
	}
	var first [1]byte
	if _, err := section.ReadAt(first[:], 0); err != nil || first[0] != 0x91 {
		t.Fatalf("wrong file range, first byte %x, error %v", first[0], err)
	}
}
