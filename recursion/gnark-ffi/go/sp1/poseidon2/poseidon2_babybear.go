package poseidon2

import (
	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/sp1-recursion-gnark/sp1/babybear"
)

const BABYBEAR_WIDTH = 16
const BABYBEAR_NUM_EXTERNAL_ROUNDS = 8
const BABYBEAR_NUM_INTERNAL_ROUNDS = 13
const BABYBEAR_DEGREE = 7

type Poseidon2BabyBearChip struct {
	fieldApi              *babybear.Chip
	internal_linear_layer [BABYBEAR_WIDTH]babybear.Variable
	zero, one             babybear.Variable
}

func NewPoseidon2BabyBearChip(api frontend.API) *Poseidon2BabyBearChip {
	return &Poseidon2BabyBearChip{
		fieldApi: babybear.NewChip(api),
		internal_linear_layer: [BABYBEAR_WIDTH]babybear.Variable{
			babybear.NewF("2013265919"),
			babybear.NewF("1"),
			babybear.NewF("2"),
			babybear.NewF("4"),
			babybear.NewF("8"),
			babybear.NewF("16"),
			babybear.NewF("32"),
			babybear.NewF("64"),
			babybear.NewF("128"),
			babybear.NewF("256"),
			babybear.NewF("512"),
			babybear.NewF("1024"),
			babybear.NewF("2048"),
			babybear.NewF("4096"),
			babybear.NewF("8192"),
			babybear.NewF("32768"),
		},
		zero: babybear.NewF("0"),
		one:  babybear.NewF("1"),
	}
}

func (p *Poseidon2BabyBearChip) PermuteMut(state *[BABYBEAR_WIDTH]babybear.Variable) {
	// The initial linear layer.
	p.matrix_permute_mut(state)

	// The first half of the external rounds.
	rounds := BABYBEAR_NUM_EXTERNAL_ROUNDS + BABYBEAR_NUM_INTERNAL_ROUNDS
	rounds_f_beginning := BABYBEAR_NUM_EXTERNAL_ROUNDS / 2
	for r := 0; r < rounds_f_beginning; r++ {
		p.add_rc(state, RC16[r])
		p.sbox(state)
		p.matrix_permute_mut(state)
	}

	// The internal rounds.
	p_end := rounds_f_beginning + BABYBEAR_NUM_INTERNAL_ROUNDS
	for r := rounds_f_beginning; r < p_end; r++ {
		state[0] = p.fieldApi.AddF(state[0], RC16[r][0])
		state[0] = p.sbox_p(state[0])
		p.diffusion_permute_mut(state)
	}

	// The second half of the external rounds.
	for r := p_end; r < rounds; r++ {
		p.add_rc(state, RC16[r])
		p.sbox(state)
		p.matrix_permute_mut(state)
	}
}

func (p *Poseidon2BabyBearChip) add_rc(state *[BABYBEAR_WIDTH]babybear.Variable, rc [BABYBEAR_WIDTH]babybear.Variable) {
	for i := 0; i < BABYBEAR_WIDTH; i++ {
		state[i] = p.fieldApi.AddF(state[i], rc[i])
	}
}

func (p *Poseidon2BabyBearChip) sbox_p(input babybear.Variable) babybear.Variable {
	if BABYBEAR_DEGREE != 7 {
		panic("DEGREE is assumed to be 7")
	}

	squared := p.fieldApi.MulF(input, input)
	input_4 := p.fieldApi.MulF(squared, squared)
	input_6 := p.fieldApi.MulF(squared, input_4)
	return p.fieldApi.MulF(input_6, input)
}

func (p *Poseidon2BabyBearChip) sbox(state *[BABYBEAR_WIDTH]babybear.Variable) {
	for i := 0; i < BABYBEAR_WIDTH; i++ {
		state[i] = p.sbox_p(state[i])
	}
}

func (p *Poseidon2BabyBearChip) matrix_permute_mut(state *[BABYBEAR_WIDTH]babybear.Variable) {
	// First, we apply M_4 to each consecutive four elements of the state.
	// In Appendix B's terminology, this replaces each x_i with x_i'.
	for i := 0; i < BABYBEAR_WIDTH; i += 4 {
		p.apply_m_4(state[i : i+4])
	}

	// Now, we apply the outer circulant matrix (to compute the y_i values).

	// We first precompute the four sums of every four elements.
	sums := [4]babybear.Variable{p.zero, p.zero, p.zero, p.zero}
	for i := 0; i < 4; i++ {
		for j := 0; j < BABYBEAR_WIDTH; j += 4 {
			sums[i] = p.fieldApi.AddF(sums[i], state[i+j])
		}
	}

	// The formula for each y_i involves 2x_i' term and x_j' terms for each j that equals i mod 4.
	// In other words, we can add a single copy of x_i' to the appropriate one of our precomputed sums
	for i := 0; i < BABYBEAR_WIDTH; i++ {
		state[i] = p.fieldApi.AddF(state[i], sums[i%4])
	}
}

// Multiply a 4-element vector x by M_4, in place.
// This uses the formula from the start of Appendix B, with multiplications unrolled into additions.
func (p *Poseidon2BabyBearChip) apply_m_4(x []babybear.Variable) {
	t0 := p.fieldApi.AddF(x[0], x[1])
	t1 := p.fieldApi.AddF(x[2], x[3])
	t2 := p.fieldApi.AddF(x[1], x[1])
	t2 = p.fieldApi.AddF(t2, t1)
	t3 := p.fieldApi.AddF(x[3], x[3])
	t3 = p.fieldApi.AddF(t3, t0)
	t4 := p.fieldApi.AddF(t1, t1)
	t4 = p.fieldApi.AddF(t4, t1)
	t4 = p.fieldApi.AddF(t4, t1)
	t4 = p.fieldApi.AddF(t4, t3)
	t5 := p.fieldApi.AddF(t0, t0)
	t5 = p.fieldApi.AddF(t5, t0)
	t5 = p.fieldApi.AddF(t5, t0)
	t5 = p.fieldApi.AddF(t5, t2)
	t6 := p.fieldApi.AddF(t3, t5)
	t7 := p.fieldApi.AddF(t2, t4)
	x[0] = t6
	x[1] = t5
	x[2] = t7
	x[3] = t4
}

func (p *Poseidon2BabyBearChip) diffusion_permute_mut(state *[BABYBEAR_WIDTH]babybear.Variable) {
	sum := p.zero
	for i := 0; i < BABYBEAR_WIDTH; i++ {
		sum = p.fieldApi.AddF(sum, state[i])
	}

	for i := 0; i < BABYBEAR_WIDTH; i++ {
		state[i] = p.fieldApi.MulF(state[i], p.internal_linear_layer[i])
		state[i] = p.fieldApi.AddF(state[i], sum)
	}
}
