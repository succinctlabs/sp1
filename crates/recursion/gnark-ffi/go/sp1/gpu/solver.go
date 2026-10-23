//go:build cuda

package gpu

import (
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/field/pool"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	csolver "github.com/consensys/gnark/constraint/solver"
)

// levelSolver mirrors gnark's bn254 solver for SparseR1CS. It differs in how it schedules levels: workers
// spin on a shared epoch instead of exchanging tasks over channels, and solved wires are counted per
// worker. It reads gates from the trace instead of the instructions, which it frees.
type levelSolver struct {
	*cs.SparseR1CS
	values []fr.Element
	solved []bool
	hints  map[csolver.HintID]csolver.Hint

	wires    []uint32
	sel      [5]selector
	n        int
	mappings []constraint.HintMapping

	nbWorkers int
	epoch     atomic.Uint64
	level     []uint32
	next      atomic.Int64
	pending   atomic.Int64
	failed    atomic.Bool
	errMu     sync.Mutex
	err       error
	counts    []paddedCount
}

type paddedCount struct {
	n uint64
	_ [7]uint64
}

const (
	minParallelLevel = 256
	minChunk         = 4
	chunkDiv         = 16
	// Beyond this, cross-core traffic on freshly solved wires costs more than the extra workers gain.
	maxWorkers = 16
	epochStop  = ^uint64(0)
	// Levels hold the trace row of a gate, or hintCode with the index of a hint mapping.
	hintCode = 1 << 31
	skipCode = ^uint32(0)
)

// newSolver solves spr from the wires and selectors of its n-row trace. It rewrites spr's levels and frees its
// instructions and calldata.
func newSolver(spr *cs.SparseR1CS, wires []uint32, sel [5]selector) (*levelSolver, error) {
	nbWires := len(spr.Public) + len(spr.Secret) + spr.NbInternalVariables
	s := &levelSolver{
		SparseR1CS: spr,
		solved:     make([]bool, nbWires),
		nbWorkers:  min(runtime.GOMAXPROCS(0), maxWorkers),
		wires:      wires,
		sel:        sel,
		n:          len(wires) / 3,
	}
	code := make([]uint32, len(spr.Instructions))
	row := uint32(len(spr.Public))
	var c constraint.SparseR1C
	for i, inst := range spr.Instructions {
		switch b := spr.Blueprints[inst.BlueprintID].(type) {
		case *constraint.BlueprintGenericSparseR1C[constraint.U64]:
			b.DecompressSparseR1C(&c, inst.Unpack(&spr.System))
			// gnark skips the constraints that enforce the commitment when solving.
			if code[i] = row; c.Commitment != constraint.NOT {
				code[i] = skipCode
			}
			row++
		case constraint.BlueprintSparseR1C:
			code[i] = row
			row++
		case constraint.BlueprintHint:
			var h constraint.HintMapping
			b.DecompressHint(&h, inst.Unpack(&spr.System))
			code[i] = hintCode | uint32(len(s.mappings))
			s.mappings = append(s.mappings, h)
		default:
			return nil, fmt.Errorf("gpu: unsupported blueprint %T", b)
		}
	}
	for l, level := range spr.Levels {
		kept := level[:0]
		for _, i := range level {
			if code[i] != skipCode {
				kept = append(kept, code[i])
			}
		}
		spr.Levels[l] = kept
	}
	spr.Instructions, spr.CallData = nil, nil
	return s, nil
}

func (s *levelSolver) solve(witness fr.Vector, opts ...csolver.Option) error {
	opt, err := csolver.NewConfig(opts...)
	if err != nil {
		return err
	}
	if len(witness) != len(s.Public)+len(s.Secret) {
		return fmt.Errorf("invalid witness size, got %d, expected %d", len(witness), len(s.Public)+len(s.Secret))
	}
	var missing []string
	for hintUUID, hintID := range s.MHintsDependencies {
		if _, ok := opt.HintFunctions[hintUUID]; !ok {
			missing = append(missing, hintID)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("solver missing hint(s): %v", missing)
	}
	s.hints = opt.HintFunctions
	for i := range s.Blueprints {
		if b, ok := s.Blueprints[i].(constraint.BlueprintStateful[constraint.U64]); ok {
			b.Reset()
		}
	}

	clear(s.solved)
	s.values = make([]fr.Element, len(s.solved))
	copy(s.values, witness)
	for i := range witness {
		s.solved[i] = true
	}
	s.err = nil
	s.failed.Store(false)
	s.counts = make([]paddedCount, s.nbWorkers)
	s.counts[0].n = uint64(len(witness))

	if err := s.run(); err != nil {
		return err
	}
	var nbSolved uint64
	for i := range s.counts {
		nbSolved += s.counts[i].n
	}
	if int(nbSolved) != len(s.values) {
		return errors.New("solver didn't assign a value to all wires")
	}
	return nil
}

func (s *levelSolver) run() error {
	var wg sync.WaitGroup
	start := s.epoch.Load()
	for w := 1; w < s.nbWorkers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			s.worker(w, start)
		}(w)
	}
	defer func() {
		s.epoch.Store(epochStop)
		wg.Wait()
		s.epoch.Store(0)
	}()

	for _, level := range s.Levels {
		if len(level) < minParallelLevel || s.nbWorkers == 1 {
			for _, i := range level {
				if err := s.process(0, i); err != nil {
					return err
				}
			}
			continue
		}
		s.level = level
		s.next.Store(0)
		s.pending.Store(int64(s.nbWorkers - 1))
		s.epoch.Add(1)
		s.drain(0)
		for s.pending.Load() > 0 {
		}
		if s.failed.Load() {
			return s.err
		}
	}
	return nil
}

func (s *levelSolver) worker(w int, seen uint64) {
	for spins := 0; ; spins++ {
		e := s.epoch.Load()
		if e == epochStop {
			return
		}
		if e == seen {
			if spins&1023 == 1023 {
				runtime.Gosched()
			}
			continue
		}
		seen = e
		s.drain(w)
		s.pending.Add(-1)
	}
}

func (s *levelSolver) drain(w int) {
	level := s.level
	chunk := max(minChunk, len(level)/(chunkDiv*s.nbWorkers))
	for !s.failed.Load() {
		start := int(s.next.Add(int64(chunk))) - chunk
		if start >= len(level) {
			return
		}
		for _, i := range level[start:min(len(level), start+chunk)] {
			if err := s.process(w, i); err != nil {
				s.errMu.Lock()
				if s.err == nil {
					s.err = err
				}
				s.errMu.Unlock()
				s.failed.Store(true)
				return
			}
		}
	}
}

func (s *levelSolver) process(w int, code uint32) error {
	if code&hintCode != 0 {
		return s.solveWithHint(w, &s.mappings[code&^hintCode])
	}
	if err := s.solveGate(w, int(code)); err != nil {
		return fmt.Errorf("constraint #%d is not satisfied: %w", int(code)-len(s.Public), err)
	}
	return nil
}

// solveGate mirrors gnark's BlueprintGenericSparseR1C.Solve for the gate qL⋅xa + qR⋅xb + qO⋅xc + qM⋅xa⋅xb + qC = 0
// of row j, which also covers its specialized blueprints.
func (s *levelSolver) solveGate(w, j int) error {
	xa, xb, xc := s.wires[j], s.wires[s.n+j], s.wires[2*s.n+j]
	var q [5]uint32
	for k := range q {
		q[k] = s.sel[k].cids[s.sel[k].idx[j]]
	}
	ql, qr, qm, qo, qc := q[0], q[1], q[2], q[3], q[4]
	term := func(cID, vID uint32) fr.Element { return s.computeTerm(constraint.Term{CID: cID, VID: vID}) }
	switch {
	case !s.solved[xa], !s.solved[xb]:
		// Solving for L: L(qL+qM⋅R) + qR⋅R + qO⋅O + qC = 0, and likewise for R.
		x, y, qx, qy := xa, xb, ql, qr
		if s.solved[xa] {
			x, y, qx, qy = xb, xa, qr, ql
		}
		den := term(qm, y)
		den.Add(&den, &s.Coefficients[qx])
		if den.IsZero() {
			return errors.New("division by 0")
		}
		den.Inverse(&den)
		num, o := term(qy, y), term(qo, xc)
		num.Add(&num, &o).Add(&num, &s.Coefficients[qc]).Mul(&num, &den).Neg(&num)
		s.set(w, int(x), num)
	case !s.solved[xc]:
		o, l, r := term(qm, xa), term(ql, xa), term(qr, xb)
		o.Mul(&o, &s.values[xb]).Add(&o, &l).Add(&o, &r).Add(&o, &s.Coefficients[qc])
		switch qo {
		case constraint.CoeffIdMinusOne:
		case constraint.CoeffIdOne:
			o.Neg(&o)
		default:
			var den fr.Element
			if den.Inverse(&s.Coefficients[qo]); den.IsZero() {
				return errors.New("division by 0")
			}
			o.Mul(&o, &den).Neg(&o)
		}
		s.set(w, int(xc), o)
	default:
		o, l, r := term(qm, xa), term(ql, xa), term(qr, xb)
		t := term(qo, xc)
		o.Mul(&o, &s.values[xb]).Add(&o, &l).Add(&o, &r).Add(&o, &t).Add(&o, &s.Coefficients[qc])
		if !o.IsZero() {
			return errors.New("qL⋅xa + qR⋅xb + qO⋅xc + qM⋅(xaxb) + qC != 0")
		}
	}
	return nil
}

func (s *levelSolver) set(w int, id int, value fr.Element) {
	if s.solved[id] {
		panic("solving the same wire twice should never happen.")
	}
	s.values[id] = value
	s.solved[id] = true
	s.counts[w].n++
}

func (s *levelSolver) computeTerm(t constraint.Term) fr.Element {
	cID, vID := t.CoeffID(), t.WireID()
	if t.IsConstant() {
		return s.Coefficients[cID]
	}
	if cID != 0 && !s.solved[vID] {
		panic("computing a term with an unsolved wire")
	}
	switch cID {
	case constraint.CoeffIdZero:
		return fr.Element{}
	case constraint.CoeffIdOne:
		return s.values[vID]
	case constraint.CoeffIdTwo:
		var res fr.Element
		res.Double(&s.values[vID])
		return res
	case constraint.CoeffIdMinusOne:
		var res fr.Element
		res.Neg(&s.values[vID])
		return res
	default:
		var res fr.Element
		res.Mul(&s.Coefficients[cID], &s.values[vID])
		return res
	}
}

func (s *levelSolver) accumulateInto(t constraint.Term, r *fr.Element) {
	cID := t.CoeffID()
	if t.IsConstant() {
		r.Add(r, &s.Coefficients[cID])
		return
	}
	v := s.computeTerm(t)
	r.Add(r, &v)
}

func (s *levelSolver) solveWithHint(w int, h *constraint.HintMapping) error {
	f, ok := s.hints[h.HintID]
	if !ok {
		return errors.New("missing hint function")
	}
	nbInputs := len(h.Inputs)
	nbOutputs := int(h.OutputRange.End - h.OutputRange.Start)
	inputs := make([]*big.Int, nbInputs)
	outputs := make([]*big.Int, nbOutputs)
	for i := 0; i < nbOutputs; i++ {
		outputs[i] = pool.BigInt.Get()
		outputs[i].SetUint64(0)
	}
	q := pool.BigInt.Get()
	q.Set(fr.Modulus())
	for i := 0; i < nbInputs; i++ {
		var v fr.Element
		for _, term := range h.Inputs[i] {
			s.accumulateInto(term, &v)
		}
		inputs[i] = pool.BigInt.Get()
		v.BigInt(inputs[i])
	}
	err := f(q, inputs, outputs)
	var v fr.Element
	for i := range outputs {
		v.SetBigInt(outputs[i])
		s.set(w, int(h.OutputRange.Start)+i, v)
		pool.BigInt.Put(outputs[i])
	}
	for i := range inputs {
		pool.BigInt.Put(inputs[i])
	}
	pool.BigInt.Put(q)
	return err
}

// newTrace returns gnark's trace for n rows: the wire ids of L for all rows, then R, then O, and the selectors
// ql, qr, qm, qo and qk.
func newTrace(spr *cs.SparseR1CS, n int) ([]uint32, [5]selector, error) {
	w := make([]uint32, 3*n)
	var sel [5]selector
	var slot [5][]uint32
	for k := range sel {
		sel[k] = selector{idx: make([]uint16, n), table: []fr.Element{{}}, cids: []uint32{constraint.CoeffIdZero}}
		slot[k] = make([]uint32, len(spr.Coefficients))
		slot[k][constraint.CoeffIdZero] = 1
	}
	set := func(k, row int, cID uint32) error {
		if slot[k][cID] == 0 {
			if len(sel[k].table) == 1<<16 {
				return fmt.Errorf("gpu: selector has more than 2^16 distinct values")
			}
			sel[k].table = append(sel[k].table, spr.Coefficients[cID])
			sel[k].cids = append(sel[k].cids, cID)
			slot[k][cID] = uint32(len(sel[k].table))
		}
		sel[k].idx[row] = uint16(slot[k][cID] - 1)
		return nil
	}
	for i := range spr.Public {
		w[i] = uint32(i)
		set(0, i, constraint.CoeffIdMinusOne)
	}
	j := len(spr.Public)
	var c constraint.SparseR1C
	for _, inst := range spr.Instructions {
		if bc, ok := spr.Blueprints[inst.BlueprintID].(constraint.BlueprintSparseR1C); ok {
			bc.DecompressSparseR1C(&c, inst.Unpack(&spr.System))
			w[j], w[n+j], w[2*n+j] = c.XA, c.XB, c.XC
			for k, cID := range [5]uint32{c.QL, c.QR, c.QM, c.QO, c.QC} {
				if err := set(k, j, cID); err != nil {
					return nil, sel, err
				}
			}
			j++
		}
	}
	return w, sel, nil
}

// permutation returns gnark's copy constraint permutation, which maps each position of a wire to its previous
// position, and its first position to its last.
func permutation(wires []uint32, nbWires int) []uint32 {
	last := make([]uint32, nbWires)
	for i, w := range wires {
		last[w] = uint32(i)
	}
	sigma := make([]uint32, len(wires))
	for i, w := range wires {
		sigma[i], last[w] = last[w], uint32(i)
	}
	return sigma
}
