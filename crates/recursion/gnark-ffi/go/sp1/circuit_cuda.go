//go:build cuda

package sp1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"os"
	"runtime"
	"sync"
	"sync/atomic"

	cs "github.com/consensys/gnark/constraint/bn254"
)

// readCircuit reads a gnark constraint system without its debug info, which only describes failed constraints in
// errors but takes most of the time to decode, and decodes its calldata in parallel.
func readCircuit(path string, system *cs.R1CS) error {
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
	calldataStart := int64(len(head)) + int64(le.Uint64(head[32:])+le.Uint64(head[40:]))
	calldataLen := le.Uint64(head[48:])
	var callData []uint32
	var callDataErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		calldata := make([]byte, calldataLen)
		if _, callDataErr = f.ReadAt(calldata, calldataStart); callDataErr == nil {
			callData, callDataErr = decodeCalldata(calldata)
		}
	}()
	defer wg.Wait()
	start := calldataStart + int64(calldataLen)
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

	var noCalldata [8]byte
	le.PutUint64(head[0:], le.Uint64(head[0:])-calldataLen-uint64(len(body))+uint64(len(noCalldata)+len(kept)))
	le.PutUint64(head[48:], uint64(len(noCalldata)))
	le.PutUint64(head[56:], uint64(len(kept)))
	_, err = system.ReadFrom(io.MultiReader(bytes.NewReader(head[:]),
		io.NewSectionReader(f, int64(len(head)), calldataStart-int64(len(head))), bytes.NewReader(noCalldata[:]),
		bytes.NewReader(kept), io.NewSectionReader(f, end, math.MaxInt64-end)))
	wg.Wait()
	if err != nil {
		return err
	}
	system.CallData = callData
	return callDataErr
}

// decodeCalldata decodes gnark's calldata section: a count, then unsigned varints.
func decodeCalldata(buf []byte) ([]uint32, error) {
	if len(buf) < 8 {
		return nil, io.ErrUnexpectedEOF
	}
	out := make([]uint32, binary.LittleEndian.Uint64(buf))
	buf = buf[8:]
	nb := runtime.NumCPU()
	// A chunk starts after a byte without the continuation bit, which ends a varint.
	starts := make([]int, nb+1)
	for c := 1; c <= nb; c++ {
		i := max(len(buf)*c/nb, starts[c-1], 1)
		for i < len(buf) && buf[i-1]&0x80 != 0 {
			i++
		}
		starts[c] = min(i, len(buf))
	}
	offsets := make([]int, nb+1)
	parallelChunks(nb, func(c int) {
		count := 0
		for _, b := range buf[starts[c]:starts[c+1]] {
			if b&0x80 == 0 {
				count++
			}
		}
		offsets[c+1] = count
	})
	for c := range nb {
		offsets[c+1] += offsets[c]
	}
	if offsets[nb] != len(out) {
		return nil, errors.New("invalid calldata")
	}
	var bad atomic.Bool
	parallelChunks(nb, func(c int) {
		chunk, j := buf[starts[c]:starts[c+1]], offsets[c]
		for len(chunk) > 0 {
			v, n := binary.Uvarint(chunk)
			if n <= 0 {
				bad.Store(true)
				return
			}
			out[j] = uint32(v)
			chunk, j = chunk[n:], j+1
		}
	})
	if bad.Load() {
		return nil, errors.New("invalid calldata")
	}
	return out, nil
}

func parallelChunks(nb int, f func(c int)) {
	var wg sync.WaitGroup
	for c := range nb {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f(c)
		}()
	}
	wg.Wait()
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
