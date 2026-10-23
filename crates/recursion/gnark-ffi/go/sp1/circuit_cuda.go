//go:build cuda

package sp1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"os"
)

// readCircuit reads a gnark constraint system without its debug info, which only describes failed constraints in
// errors but takes most of the time to decode.
func readCircuit(path string, system io.ReaderFrom) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	// The length of the rest, the gnark version, then the lengths of the levels, instructions, calldata and CBOR
	// body that follow, before the coefficients.
	var head [64]byte
	if _, err := io.ReadFull(f, head[:]); err != nil {
		return err
	}
	le := binary.LittleEndian
	start := int64(len(head)) + int64(le.Uint64(head[32:])+le.Uint64(head[40:])+le.Uint64(head[48:]))
	body := make([]byte, le.Uint64(head[56:]))
	if _, err := f.ReadAt(body, start); err != nil {
		return err
	}
	end := start + int64(len(body))

	if len(body) == 0 || body[0]>>5 != 5 || body[0]&31 >= 24 {
		return errors.New("unexpected constraint system encoding")
	}
	kept := []byte{body[0]}
	for i, pairs := 1, body[0]&31; pairs > 0; pairs-- {
		k, err := itemLen(body[i:])
		if err != nil {
			return err
		}
		v, err := itemLen(body[i+k:])
		if err != nil {
			return err
		}
		if key := string(body[i : i+k]); key == "\x69DebugInfo" || key == "\x66MDebug" {
			kept[0]--
		} else {
			kept = append(kept, body[i:i+k+v]...)
		}
		i += k + v
	}

	le.PutUint64(head[0:], le.Uint64(head[0:])-uint64(len(body))+uint64(len(kept)))
	le.PutUint64(head[56:], uint64(len(kept)))
	_, err = system.ReadFrom(io.MultiReader(bytes.NewReader(head[:]), io.NewSectionReader(f, int64(len(head)), start-int64(len(head))),
		bytes.NewReader(kept), io.NewSectionReader(f, end, math.MaxInt64-end)))
	return err
}

// itemLen returns the length of the definite-length CBOR item at the start of b.
func itemLen(b []byte) (int, error) {
	i := 0
	for pending := uint64(1); pending > 0; pending-- {
		if i >= len(b) {
			return 0, io.ErrUnexpectedEOF
		}
		major, n := b[i]>>5, uint64(b[i]&31)
		i++
		if n >= 24 {
			if n > 27 {
				return 0, errors.New("unsupported CBOR item")
			}
			k := 1 << (n - 24)
			if i+k > len(b) {
				return 0, io.ErrUnexpectedEOF
			}
			n = 0
			for _, c := range b[i : i+k] {
				n = n<<8 | uint64(c)
			}
			i += k
		}
		switch major {
		case 2, 3:
			if n > uint64(len(b)-i) {
				return 0, io.ErrUnexpectedEOF
			}
			i += int(n)
		case 4:
			pending += n
		case 5:
			pending += 2 * n
		case 6:
			pending++
		}
	}
	return i, nil
}
