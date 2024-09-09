package babybear

/*
#include "../../babybear.h"
*/
import "C"

import (
	"fmt"
	"math"
	"math/big"
	"os"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

var modulus = new(big.Int).SetUint64(2013265921)

func init() {
	// These functions must be public so Gnark's hint system can access them.
	solver.RegisterHint(InvFHint)
	solver.RegisterHint(InvEHint)
	solver.RegisterHint(ReduceHint)
	solver.RegisterHint(SplitLimbsHint)
}

type Variable struct {
	Value  frontend.Variable
	NbBits uint
}

type ExtensionVariable struct {
	Value [4]Variable
}

type Chip struct {
	api          frontend.API
	RangeChecker frontend.Rangechecker
}

func NewChip(api frontend.API) *Chip {
	return &Chip{
		api:          api,
		RangeChecker: rangecheck.New(api),
	}
}

func Zero() Variable {
	return Variable{
		Value:  frontend.Variable("0"),
		NbBits: 1,
	}
}

func One() Variable {
	return Variable{
		Value:  frontend.Variable("1"),
		NbBits: 1,
	}
}

func NewF(value string) Variable {
	if value == "0" {
		return Zero()
	} else if value == "1" {
		return One()
	}
	return Variable{
		Value:  frontend.Variable(value),
		NbBits: 31,
	}
}

func NewE(value []string) ExtensionVariable {
	a := NewF(value[0])
	b := NewF(value[1])
	c := NewF(value[2])
	d := NewF(value[3])
	return ExtensionVariable{Value: [4]Variable{a, b, c, d}}
}

func Felts2Ext(a, b, c, d Variable) ExtensionVariable {
	return ExtensionVariable{Value: [4]Variable{a, b, c, d}}
}

func (c *Chip) AddF(a, b Variable) Variable {
	var maxBits uint
	if a.NbBits > b.NbBits {
		maxBits = a.NbBits
	} else {
		maxBits = b.NbBits
	}
	return c.reduceFast(Variable{
		Value:  c.api.Add(a.Value, b.Value),
		NbBits: maxBits + 1,
	})
}

func (c *Chip) SubF(a, b Variable) Variable {
	negB := c.negF(b)
	return c.AddF(a, negB)
}

func (c *Chip) MulF(a, b Variable) Variable {
	return c.reduceFast(Variable{
		Value:  c.api.Mul(a.Value, b.Value),
		NbBits: a.NbBits + b.NbBits,
	})
}

func (c *Chip) MulFConst(a Variable, b int) Variable {
	return c.reduceFast(Variable{
		Value:  c.api.Mul(a.Value, b),
		NbBits: a.NbBits + 4,
	})
}

func (c *Chip) negF(a Variable) Variable {
	if a.NbBits <= 30 {
		return Variable{Value: c.api.Sub(modulus, a.Value), NbBits: 31}
	}

	ub := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(a.NbBits)), big.NewInt(0))
	divisor := new(big.Int).Div(ub, modulus)
	divisorPlusOne := new(big.Int).Add(divisor, big.NewInt(1))
	liftedModulus := new(big.Int).Mul(divisorPlusOne, modulus)

	return c.reduceFast(Variable{
		Value:  c.api.Sub(liftedModulus, a.Value),
		NbBits: a.NbBits + 1,
	})
}

func (c *Chip) invF(in Variable) Variable {
	in = c.ReduceSlow(in)
	result, err := c.api.Compiler().NewHint(InvFHint, 1, in.Value)
	if err != nil {
		panic(err)
	}

	xinv := Variable{
		Value:  result[0],
		NbBits: 31,
	}
	if os.Getenv("GROTH16") != "1" {
		c.RangeChecker.Check(result[0], 31)
	} else {
		c.api.ToBinary(result[0], 31)
	}
	product := c.MulF(in, xinv)
	c.AssertIsEqualF(product, NewF("1"))

	return xinv
}

func (c *Chip) DivF(a, b Variable) Variable {
	bInv := c.invF(b)
	return c.MulF(a, bInv)
}

func (c *Chip) AssertIsEqualF(a, b Variable) {
	a2 := c.ReduceSlow(a)
	b2 := c.ReduceSlow(b)
	c.api.AssertIsEqual(a2.Value, b2.Value)
}

func (c *Chip) AssertNotEqualF(a, b Variable) {
	a2 := c.ReduceSlow(a)
	b2 := c.ReduceSlow(b)
	c.api.AssertIsDifferent(a2.Value, b2.Value)
}

func (c *Chip) AssertIsEqualE(a, b ExtensionVariable) {
	c.AssertIsEqualF(a.Value[0], b.Value[0])
	c.AssertIsEqualF(a.Value[1], b.Value[1])
	c.AssertIsEqualF(a.Value[2], b.Value[2])
	c.AssertIsEqualF(a.Value[3], b.Value[3])
}

func (c *Chip) SelectF(cond frontend.Variable, a, b Variable) Variable {
	var nbBits uint
	if a.NbBits > b.NbBits {
		nbBits = a.NbBits
	} else {
		nbBits = b.NbBits
	}
	return Variable{
		Value:  c.api.Select(cond, a.Value, b.Value),
		NbBits: nbBits,
	}
}

func (c *Chip) SelectE(cond frontend.Variable, a, b ExtensionVariable) ExtensionVariable {
	return ExtensionVariable{
		Value: [4]Variable{
			c.SelectF(cond, a.Value[0], b.Value[0]),
			c.SelectF(cond, a.Value[1], b.Value[1]),
			c.SelectF(cond, a.Value[2], b.Value[2]),
			c.SelectF(cond, a.Value[3], b.Value[3]),
		},
	}
}

func (c *Chip) AddEF(a ExtensionVariable, b Variable) ExtensionVariable {
	v1 := c.AddF(a.Value[0], b)
	return ExtensionVariable{Value: [4]Variable{v1, a.Value[1], a.Value[2], a.Value[3]}}
}

func (c *Chip) AddE(a, b ExtensionVariable) ExtensionVariable {
	v1 := c.AddF(a.Value[0], b.Value[0])
	v2 := c.AddF(a.Value[1], b.Value[1])
	v3 := c.AddF(a.Value[2], b.Value[2])
	v4 := c.AddF(a.Value[3], b.Value[3])
	return ExtensionVariable{Value: [4]Variable{v1, v2, v3, v4}}
}

func (c *Chip) SubE(a, b ExtensionVariable) ExtensionVariable {
	v1 := c.SubF(a.Value[0], b.Value[0])
	v2 := c.SubF(a.Value[1], b.Value[1])
	v3 := c.SubF(a.Value[2], b.Value[2])
	v4 := c.SubF(a.Value[3], b.Value[3])
	return ExtensionVariable{Value: [4]Variable{v1, v2, v3, v4}}
}

func (c *Chip) SubEF(a ExtensionVariable, b Variable) ExtensionVariable {
	v1 := c.SubF(a.Value[0], b)
	return ExtensionVariable{Value: [4]Variable{v1, a.Value[1], a.Value[2], a.Value[3]}}
}

func (c *Chip) MulE(a, b ExtensionVariable) ExtensionVariable {
	v2 := [4]Variable{
		Zero(),
		Zero(),
		Zero(),
		Zero(),
	}

	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			if i+j >= 4 {
				v2[i+j-4] = c.AddF(v2[i+j-4], c.MulFConst(c.MulF(a.Value[i], b.Value[j]), 11))
			} else {
				v2[i+j] = c.AddF(v2[i+j], c.MulF(a.Value[i], b.Value[j]))
			}
		}
	}

	return ExtensionVariable{Value: v2}
}

func (c *Chip) MulEF(a ExtensionVariable, b Variable) ExtensionVariable {
	v1 := c.MulF(a.Value[0], b)
	v2 := c.MulF(a.Value[1], b)
	v3 := c.MulF(a.Value[2], b)
	v4 := c.MulF(a.Value[3], b)
	return ExtensionVariable{Value: [4]Variable{v1, v2, v3, v4}}
}

func (c *Chip) InvE(in ExtensionVariable) ExtensionVariable {
	in.Value[0] = c.ReduceSlow(in.Value[0])
	in.Value[1] = c.ReduceSlow(in.Value[1])
	in.Value[2] = c.ReduceSlow(in.Value[2])
	in.Value[3] = c.ReduceSlow(in.Value[3])
	result, err := c.api.Compiler().NewHint(InvEHint, 4, in.Value[0].Value, in.Value[1].Value, in.Value[2].Value, in.Value[3].Value)
	if err != nil {
		panic(err)
	}

	xinv := Variable{Value: result[0], NbBits: 31}
	yinv := Variable{Value: result[1], NbBits: 31}
	zinv := Variable{Value: result[2], NbBits: 31}
	linv := Variable{Value: result[3], NbBits: 31}
	if os.Getenv("GROTH16") != "1" {
		c.RangeChecker.Check(result[0], 31)
		c.RangeChecker.Check(result[1], 31)
		c.RangeChecker.Check(result[2], 31)
		c.RangeChecker.Check(result[3], 31)
	} else {
		c.api.ToBinary(result[0], 31)
		c.api.ToBinary(result[1], 31)
		c.api.ToBinary(result[2], 31)
		c.api.ToBinary(result[3], 31)
	}
	out := ExtensionVariable{Value: [4]Variable{xinv, yinv, zinv, linv}}

	product := c.MulE(in, out)
	c.AssertIsEqualE(product, NewE([]string{"1", "0", "0", "0"}))

	return out
}

func (c *Chip) Ext2Felt(in ExtensionVariable) [4]Variable {
	return in.Value
}

func (c *Chip) DivE(a, b ExtensionVariable) ExtensionVariable {
	bInv := c.InvE(b)
	return c.MulE(a, bInv)
}

func (c *Chip) DivEF(a ExtensionVariable, b Variable) ExtensionVariable {
	bInv := c.invF(b)
	return c.MulEF(a, bInv)
}

func (c *Chip) NegE(a ExtensionVariable) ExtensionVariable {
	v1 := c.negF(a.Value[0])
	v2 := c.negF(a.Value[1])
	v3 := c.negF(a.Value[2])
	v4 := c.negF(a.Value[3])
	return ExtensionVariable{Value: [4]Variable{v1, v2, v3, v4}}
}

func (c *Chip) ToBinary(in Variable) []frontend.Variable {
	return c.api.ToBinary(c.ReduceSlow(in).Value, 32)
}

func (p *Chip) reduceFast(x Variable) Variable {
	if x.NbBits >= uint(120) {
		return Variable{
			Value:  p.reduceWithMaxBits(x.Value, uint64(x.NbBits)),
			NbBits: 31,
		}
	}
	return x
}

func (p *Chip) ReduceSlow(x Variable) Variable {
	if x.NbBits <= 30 {
		return x
	}
	return Variable{
		Value:  p.reduceWithMaxBits(x.Value, uint64(x.NbBits)),
		NbBits: 31,
	}
}

func (p *Chip) reduceWithMaxBits(x frontend.Variable, maxNbBits uint64) frontend.Variable {
	if maxNbBits <= 30 {
		return x
	}
	result, err := p.api.Compiler().NewHint(ReduceHint, 2, x)
	if err != nil {
		panic(err)
	}

	quotient := result[0]
	remainder := result[1]

	// TODO: Fix before 1.3.0.
	// if os.Getenv("GROTH16") != "1" {
	// 	p.RangeChecker.Check(quotient, int(maxNbBits-30))
	// } else {
	// 	p.api.ToBinary(quotient, int(maxNbBits-30))
	// }
	// Check that the remainder has size less than the BabyBear modulus, by decomposing it into a 27
	// bit limb and a 4 bit limb.
	new_result, new_err := p.api.Compiler().NewHint(SplitLimbsHint, 2, remainder)
	if new_err != nil {
		panic(new_err)
	}

	lowLimb := new_result[0]
	highLimb := new_result[1]

	// Check that the hint is correct.
	p.api.AssertIsEqual(
		p.api.Add(
			p.api.Mul(highLimb, frontend.Variable(uint64(math.Pow(2, 27)))),
			lowLimb,
		),
		remainder,
	)
	if os.Getenv("GROTH16") != "1" {
		p.RangeChecker.Check(highLimb, 4)
		p.RangeChecker.Check(lowLimb, 27)
	} else {
		p.api.ToBinary(highLimb, 4)
		p.api.ToBinary(lowLimb, 27)
	}

	// If the most significant bits are all 1, then we need to check that the least significant bits
	// are all zero in order for element to be less than the BabyBear modulus. Otherwise, we don't
	// need to do any checks, since we already know that the element is less than the BabyBear modulus.
	shouldCheck := p.api.IsZero(p.api.Sub(highLimb, uint64(math.Pow(2, 4))-1))
	p.api.AssertIsEqual(
		p.api.Select(
			shouldCheck,
			lowLimb,
			frontend.Variable(0),
		),
		frontend.Variable(0),
	)

	p.api.AssertIsEqual(x, p.api.Add(p.api.Mul(quotient, modulus), remainder))

	return remainder
}

// The hint used to compute Reduce.
func ReduceHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 1 {
		panic("reduceHint expects 1 input operand")
	}
	input := inputs[0]
	quotient := new(big.Int).Div(input, modulus)
	remainder := new(big.Int).Rem(input, modulus)
	results[0] = quotient
	results[1] = remainder
	return nil
}

func (p *Chip) ReduceE(x ExtensionVariable) ExtensionVariable {
	for i := 0; i < 4; i++ {
		x.Value[i] = p.ReduceSlow(x.Value[i])
	}
	return x
}

func InvFHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	a := C.uint(inputs[0].Uint64())
	ainv := C.babybearinv(a)
	results[0].SetUint64(uint64(ainv))
	return nil
}

// The hint used to split a BabyBear Variable into a 4 bit limb (the most significant bits) and a
// 27 bit limb.
func SplitLimbsHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 1 {
		panic("SplitLimbsHint expects 1 input operand")
	}

	// The BabyBear field element
	input := inputs[0]

	if input.Cmp(modulus) == 0 || input.Cmp(modulus) == 1 {
		return fmt.Errorf("input is not in the field")
	}

	two_27 := big.NewInt(int64(math.Pow(2, 27)))

	// The least significant bits
	results[0] = new(big.Int).Rem(input, two_27)
	// The most significant bits
	results[1] = new(big.Int).Quo(input, two_27)

	return nil
}

func InvEHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	a := C.uint(inputs[0].Uint64())
	b := C.uint(inputs[1].Uint64())
	c := C.uint(inputs[2].Uint64())
	d := C.uint(inputs[3].Uint64())
	ainv := C.babybearextinv(a, b, c, d, 0)
	binv := C.babybearextinv(a, b, c, d, 1)
	cinv := C.babybearextinv(a, b, c, d, 2)
	dinv := C.babybearextinv(a, b, c, d, 3)
	results[0].SetUint64(uint64(ainv))
	results[1].SetUint64(uint64(binv))
	results[2].SetUint64(uint64(cinv))
	results[3].SetUint64(uint64(dinv))
	return nil
}
