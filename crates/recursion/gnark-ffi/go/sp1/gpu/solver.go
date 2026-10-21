//go:build plonkcuda || groth16cuda

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
// worker. The wire values live in page-locked memory so that they can be copied to the GPU directly.
type levelSolver struct {
	*cs.SparseR1CS
	values []fr.Element
	solved []bool
	hints  map[csolver.HintID]csolver.Hint

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
)

func newSolver(spr *cs.SparseR1CS) *levelSolver {
	nbWires := len(spr.Public) + len(spr.Secret) + spr.NbInternalVariables
	values := make([]fr.Element, nbWires)
	pin(values)
	return &levelSolver{
		SparseR1CS: spr,
		values:     values,
		solved:     make([]bool, nbWires),
		nbWorkers:  min(runtime.GOMAXPROCS(0), maxWorkers),
	}
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
				if err := s.processInstruction(0, s.Instructions[i]); err != nil {
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
			if err := s.processInstruction(w, s.Instructions[i]); err != nil {
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

// processInstruction decodes the instruction and executes the blueprint-defined logic.
func (s *levelSolver) processInstruction(w int, pi constraint.PackedInstruction) error {
	blueprint := s.Blueprints[pi.BlueprintID]
	inst := pi.Unpack(&s.System)
	bs := blueprintSolver{s, w}
	if bc, ok := blueprint.(constraint.BlueprintSolvable[constraint.U64]); ok {
		if err := bc.Solve(bs, inst); err != nil {
			return fmt.Errorf("constraint #%d is not satisfied: %w", inst.ConstraintOffset, err)
		}
		return nil
	}
	if bc, ok := blueprint.(constraint.BlueprintHint); ok {
		var h constraint.HintMapping
		bc.DecompressHint(&h, inst)
		return s.solveWithHint(w, &h)
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

// blueprintSolver implements constraint.Solver for one worker.
type blueprintSolver struct {
	*levelSolver
	w int
}

func (b blueprintSolver) GetValue(cID, vID uint32) constraint.U64 {
	var r constraint.U64
	e := b.computeTerm(constraint.Term{CID: cID, VID: vID})
	copy(r[:], e[:])
	return r
}

func (b blueprintSolver) GetCoeff(cID uint32) constraint.U64 {
	var r constraint.U64
	copy(r[:], b.Coefficients[cID][:])
	return r
}

func (b blueprintSolver) SetValue(vID uint32, f constraint.U64) {
	b.set(b.w, int(vID), *(*fr.Element)(f[:]))
}

func (b blueprintSolver) IsSolved(vID uint32) bool {
	return b.solved[vID]
}

func (b blueprintSolver) Read(calldata []uint32) (constraint.U64, int) {
	if calldata[0] != 1 {
		panic("invalid calldata")
	}
	return b.GetValue(calldata[1], calldata[2]), 3
}

// lroWires returns the wire ids of L, R and O for each row of the n-row trace, as in gnark's
// evaluateLROSmallDomain: L for all rows, then R, then O.
func lroWires(spr *cs.SparseR1CS, n int) []uint32 {
	w := make([]uint32, 3*n)
	for i := range spr.Public {
		w[i] = uint32(i)
	}
	j := len(spr.Public)
	var c constraint.SparseR1C
	for _, inst := range spr.Instructions {
		if bc, ok := spr.Blueprints[inst.BlueprintID].(constraint.BlueprintSparseR1C); ok {
			bc.DecompressSparseR1C(&c, inst.Unpack(&spr.System))
			w[j], w[n+j], w[2*n+j] = c.XA, c.XB, c.XC
			j++
		}
	}
	return w
}
