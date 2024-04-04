package poseidon2

import (
	"github.com/consensys/gnark/frontend"
)

const WIDTH = 3
const NUM_EXTERNAL_ROUNDS = 8
const NUM_INTERNAL_ROUNDS = 56
const DEGREE = 5

type Poseidon2Chip struct {
	api                   frontend.API
	internal_linear_layer [WIDTH]frontend.Variable
	zero, one             frontend.Variable
}

func NewChip(api frontend.API) *Poseidon2Chip {
	return &Poseidon2Chip{
		api: api,
		internal_linear_layer: [WIDTH]frontend.Variable{
			frontend.Variable(1),
			frontend.Variable(1),
			frontend.Variable(2),
		},
		zero: frontend.Variable(0),
		one:  frontend.Variable(1),
	}
}

func (p *Poseidon2Chip) PermuteMut(state *[WIDTH]frontend.Variable) {
	// The initial linear layer.
	p.MatrixPermuteMut(state)

	// The first half of the external rounds.
	rounds := NUM_EXTERNAL_ROUNDS + NUM_INTERNAL_ROUNDS
	rounds_f_beginning := NUM_EXTERNAL_ROUNDS / 2
	for r := 0; r < rounds_f_beginning; r++ {
		p.AddRc(state, RC3[r])
		p.Sbox(state)
		p.MatrixPermuteMut(state)
	}

	// The internal rounds.
	p_end := rounds_f_beginning + NUM_INTERNAL_ROUNDS
	for r := rounds_f_beginning; r < p_end; r++ {
		state[0] = p.api.Add(state[0], RC3[r][0])
		state[0] = p.SboxP(state[0])
		p.DiffusionPermuteMut(state)
	}

	// The second half of the external rounds.
	for r := p_end; r < rounds; r++ {
		p.AddRc(state, RC3[r])
		p.Sbox(state)
		p.MatrixPermuteMut(state)
	}
}

func (p *Poseidon2Chip) AddRc(state *[WIDTH]frontend.Variable, rc [WIDTH]frontend.Variable) {
	for i := 0; i < WIDTH; i++ {
		state[i] = p.api.Add(state[i], rc[i])
	}
}

func (p *Poseidon2Chip) SboxP(input frontend.Variable) frontend.Variable {
	if DEGREE != 5 {
		panic("DEGREE is assumed to be 5")
	}
	squared := p.api.Mul(input, input)
	input_4 := p.api.Mul(squared, squared)
	return p.api.Mul(input_4, input)
}

func (p *Poseidon2Chip) Sbox(state *[WIDTH]frontend.Variable) {
	for i := 0; i < WIDTH; i++ {
		state[i] = p.SboxP(state[i])
	}
}
