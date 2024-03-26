package poseidon2

import (
	"github.com/consensys/gnark/frontend"
)

func (p *Poseidon2Chip) DiffusionPermuteMut(state *[WIDTH]frontend.Variable) {
	sum := p.zero
	for i := 0; i < WIDTH; i++ {
		sum = p.api.Add(sum, state[i])
	}

	for i := 0; i < WIDTH; i++ {
		state[i] = p.api.Mul(state[i], p.internal_linear_layer[i])
		state[i] = p.api.Add(state[i], sum)
	}
}

func (p *Poseidon2Chip) MatrixPermuteMut(state *[WIDTH]frontend.Variable) {
	sum := p.api.Add(state[0], state[1])
	sum = p.api.Add(sum, state[2])
	state[0] = p.api.Add(state[0], sum)
	state[1] = p.api.Add(state[1], sum)
	state[2] = p.api.Add(state[2], sum)
}
