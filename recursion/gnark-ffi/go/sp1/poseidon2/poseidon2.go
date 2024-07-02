package poseidon2

import (
	"github.com/consensys/gnark/frontend"
)

const width = 3
const numExternalRounds = 8
const numInternalRounds = 56
const degree = 5

type Poseidon2Chip struct {
	api                   frontend.API
	internal_linear_layer [width]frontend.Variable
	zero                  frontend.Variable
}

func NewChip(api frontend.API) *Poseidon2Chip {
	return &Poseidon2Chip{
		api: api,
		internal_linear_layer: [width]frontend.Variable{
			frontend.Variable(1),
			frontend.Variable(1),
			frontend.Variable(2),
		},
		zero: frontend.Variable(0),
	}
}

func (p *Poseidon2Chip) PermuteMut(state *[width]frontend.Variable) {
	// The initial linear layer.
	p.matrixPermuteMut(state)

	// The first half of the external rounds.
	rounds := numExternalRounds + numInternalRounds
	rounds_f_beginning := numExternalRounds / 2
	for r := 0; r < rounds_f_beginning; r++ {
		p.addRc(state, rc3[r])
		p.sbox(state)
		p.matrixPermuteMut(state)
	}

	// The internal rounds.
	p_end := rounds_f_beginning + numInternalRounds
	for r := rounds_f_beginning; r < p_end; r++ {
		state[0] = p.api.Add(state[0], rc3[r][0])
		state[0] = p.sboxP(state[0])
		p.diffusionPermuteMut(state)
	}

	// The second half of the external rounds.
	for r := p_end; r < rounds; r++ {
		p.addRc(state, rc3[r])
		p.sbox(state)
		p.matrixPermuteMut(state)
	}
}

func (p *Poseidon2Chip) addRc(state *[width]frontend.Variable, rc [width]frontend.Variable) {
	for i := 0; i < width; i++ {
		state[i] = p.api.Add(state[i], rc[i])
	}
}

func (p *Poseidon2Chip) sboxP(input frontend.Variable) frontend.Variable {
	if degree != 5 {
		panic("DEGREE is assumed to be 5")
	}
	squared := p.api.Mul(input, input)
	input_4 := p.api.Mul(squared, squared)
	return p.api.Mul(input_4, input)
}

func (p *Poseidon2Chip) sbox(state *[width]frontend.Variable) {
	for i := 0; i < width; i++ {
		state[i] = p.sboxP(state[i])
	}
}
