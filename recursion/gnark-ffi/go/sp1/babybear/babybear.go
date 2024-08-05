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
}

type Variable struct {
	Value  frontend.Variable
	NbBits uint
}

type ExtensionVariable struct {
	Value [4]Variable
}

type Chip struct {
	api                  frontend.API
	rangeChecker         frontend.Rangechecker
	ReduceMaxBitsCounter int
	AddFCounter          int
	MulFCounter          int
	AddEFCounter         int
	MulEFCounter         int
	AddECounter          int
	MulECounter          int
	ReduceMaxBitsMap     map[string]int
}

func NewChip(api frontend.API) *Chip {
	return &Chip{
		api:                  api,
		rangeChecker:         rangecheck.New(api),
		ReduceMaxBitsCounter: 0,
		ReduceMaxBitsMap:     make(map[string]int),
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
	c.AddFCounter++
	if a.NbBits > b.NbBits {
		maxBits = a.NbBits
	} else {
		maxBits = b.NbBits
	}
	curNumReduce := c.ReduceMaxBitsCounter
	retVal := c.reduceFast(Variable{
		Value:  c.api.Add(a.Value, b.Value),
		NbBits: maxBits,
	})
	c.ReduceMaxBitsMap["AddF"] += c.ReduceMaxBitsCounter - curNumReduce
	return retVal

}

func (c *Chip) SubF(a, b Variable) Variable {
	curNumReduce := c.ReduceMaxBitsCounter
	negB := c.negF(b)
	retVal := c.AddF(a, negB)
	c.ReduceMaxBitsMap["SubF"] += c.ReduceMaxBitsCounter - curNumReduce
	return retVal
}

func (c *Chip) MulF(a, b Variable) (Variable, Variable, Variable) {
	curNumReduce := c.ReduceMaxBitsCounter
	varC := a
	varD := b

	for varC.NbBits+varD.NbBits > 252 {
		if varC.NbBits > varD.NbBits {
			varC = Variable{Value: c.reduceWithMaxBits(varC.Value, uint64(varC.NbBits)), NbBits: 31}
		} else {
			varD = Variable{Value: c.reduceWithMaxBits(varD.Value, uint64(varD.NbBits)), NbBits: 31}
		}
	}
	c.MulFCounter += c.ReduceMaxBitsCounter - curNumReduce

	return Variable{
		Value:  c.api.Mul(varC.Value, varD.Value),
		NbBits: varC.NbBits + varD.NbBits,
	}, varC, varD
}

func (c *Chip) MulFConst(a Variable, b int) Variable {
	curNumReduce := c.ReduceMaxBitsCounter
	retVal := c.reduceFast(Variable{
		Value:  c.api.Mul(a.Value, b),
		NbBits: a.NbBits + 4,
	})
	c.ReduceMaxBitsMap["MulFConst"] += c.ReduceMaxBitsCounter - curNumReduce
	return retVal
}

func (c *Chip) negF(a Variable) Variable {
	var retVal Variable
	curNumReduce := c.ReduceMaxBitsCounter
	if a.NbBits == 31 {
		retVal = Variable{Value: c.api.Sub(modulus, a.Value), NbBits: 31}
	} else {
		negOne := NewF("2013265920")
		retVal, _, _ = c.MulF(a, negOne)
	}

	c.ReduceMaxBitsMap["negF"] += c.ReduceMaxBitsCounter - curNumReduce
	return retVal
}

func (c *Chip) invF(in Variable) Variable {
	curNumReduce := c.ReduceMaxBitsCounter
	in = c.ReduceSlow(in)
	result, err := c.api.Compiler().NewHint(InvFHint, 1, in.Value)
	if err != nil {
		panic(err)
	}

	xinv := Variable{
		Value:  result[0],
		NbBits: 31,
	}
	product, _, _ := c.MulF(in, xinv)
	c.AssertIsEqualF(product, NewF("1"))
	c.ReduceMaxBitsMap["invF"] += c.ReduceMaxBitsCounter - curNumReduce

	return xinv
}

func (c *Chip) AssertIsEqualF(a, b Variable) {
	curNumReduce := c.ReduceMaxBitsCounter
	a2 := c.ReduceSlow(a)
	b2 := c.ReduceSlow(b)
	c.api.AssertIsEqual(a2.Value, b2.Value)
	c.ReduceMaxBitsMap["AssertIsEqualF"] += c.ReduceMaxBitsCounter - curNumReduce
}

func (c *Chip) AssertIsEqualE(a, b ExtensionVariable) {
	curNumReduce := c.ReduceMaxBitsCounter
	c.AssertIsEqualF(a.Value[0], b.Value[0])
	c.AssertIsEqualF(a.Value[1], b.Value[1])
	c.AssertIsEqualF(a.Value[2], b.Value[2])
	c.AssertIsEqualF(a.Value[3], b.Value[3])
	c.ReduceMaxBitsMap["AssertIsEqualE"] += c.ReduceMaxBitsCounter - curNumReduce
}

func (c *Chip) SelectF(cond frontend.Variable, a, b Variable) Variable {
	curNumReduce := c.ReduceMaxBitsCounter
	var nbBits uint
	if a.NbBits > b.NbBits {
		nbBits = a.NbBits
	} else {
		nbBits = b.NbBits
	}
	retVal := Variable{
		Value:  c.api.Select(cond, a.Value, b.Value),
		NbBits: nbBits,
	}
	c.ReduceMaxBitsMap["SelectF"] += c.ReduceMaxBitsCounter - curNumReduce
	return retVal
}

func (c *Chip) SelectE(cond frontend.Variable, a, b ExtensionVariable) ExtensionVariable {
	curNumReduce := c.ReduceMaxBitsCounter
	retVal := ExtensionVariable{
		Value: [4]Variable{
			c.SelectF(cond, a.Value[0], b.Value[0]),
			c.SelectF(cond, a.Value[1], b.Value[1]),
			c.SelectF(cond, a.Value[2], b.Value[2]),
			c.SelectF(cond, a.Value[3], b.Value[3]),
		},
	}
	c.ReduceMaxBitsMap["SelectE"] += c.ReduceMaxBitsCounter - curNumReduce
	return retVal
}

func (c *Chip) AddEF(a ExtensionVariable, b Variable) ExtensionVariable {
	c.AddEFCounter++
	curNumReduce := c.ReduceMaxBitsCounter
	v1 := c.AddF(a.Value[0], b)
	c.ReduceMaxBitsMap["AddEF"] += c.ReduceMaxBitsCounter - curNumReduce
	return ExtensionVariable{Value: [4]Variable{v1, a.Value[1], a.Value[2], a.Value[3]}}
}

func (c *Chip) AddE(a, b ExtensionVariable) ExtensionVariable {
	c.AddECounter++
	curNumReduce := c.ReduceMaxBitsCounter
	v1 := c.AddF(a.Value[0], b.Value[0])
	v2 := c.AddF(a.Value[1], b.Value[1])
	v3 := c.AddF(a.Value[2], b.Value[2])
	v4 := c.AddF(a.Value[3], b.Value[3])
	c.ReduceMaxBitsMap["AddE"] += c.ReduceMaxBitsCounter - curNumReduce
	return ExtensionVariable{Value: [4]Variable{v1, v2, v3, v4}}
}

func (c *Chip) SubE(a, b ExtensionVariable) ExtensionVariable {
	curNumReduce := c.ReduceMaxBitsCounter
	v1 := c.SubF(a.Value[0], b.Value[0])
	v2 := c.SubF(a.Value[1], b.Value[1])
	v3 := c.SubF(a.Value[2], b.Value[2])
	v4 := c.SubF(a.Value[3], b.Value[3])
	c.ReduceMaxBitsMap["SubE"] += c.ReduceMaxBitsCounter - curNumReduce
	return ExtensionVariable{Value: [4]Variable{v1, v2, v3, v4}}
}

func (c *Chip) SubEF(a ExtensionVariable, b Variable) ExtensionVariable {
	curNumReduce := c.ReduceMaxBitsCounter
	v1 := c.SubF(a.Value[0], b)
	c.ReduceMaxBitsMap["SubEF"] += c.ReduceMaxBitsCounter - curNumReduce
	return ExtensionVariable{Value: [4]Variable{v1, a.Value[1], a.Value[2], a.Value[3]}}
}

func (c *Chip) MulE(a, b ExtensionVariable) ExtensionVariable {
	c.MulECounter++
	v2 := [4]Variable{
		Zero(),
		Zero(),
		Zero(),
		Zero(),
	}

	newA := a
	newB := b
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			newVal, newAEntry, newBEntry := c.MulF(newA.Value[i], newB.Value[j])
			if i+j >= 4 {
				v2[i+j-4] = c.AddF(v2[i+j-4], c.MulFConst(newVal, 11))
			} else {
				v2[i+j] = c.AddF(v2[i+j], newVal)
			}
			newA.Value[i] = newAEntry
			newB.Value[j] = newBEntry
		}
	}

	return ExtensionVariable{Value: v2}

}

func (c *Chip) MulEF(a ExtensionVariable, b Variable) ExtensionVariable {
	c.MulEFCounter++
	curNumReduce := c.ReduceMaxBitsCounter
	v1, _, newB := c.MulF(a.Value[0], b)
	v2, _, newB := c.MulF(a.Value[1], newB)
	v3, _, newB := c.MulF(a.Value[2], newB)
	v4, _, _ := c.MulF(a.Value[3], newB)
	c.ReduceMaxBitsMap["MulEF"] += c.ReduceMaxBitsCounter - curNumReduce
	return ExtensionVariable{Value: [4]Variable{v1, v2, v3, v4}}
}

func (c *Chip) InvE(in ExtensionVariable) ExtensionVariable {
	curNumReduce := c.ReduceMaxBitsCounter
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
	out := ExtensionVariable{Value: [4]Variable{xinv, yinv, zinv, linv}}

	product := c.MulE(in, out)
	c.AssertIsEqualE(product, NewE([]string{"1", "0", "0", "0"}))
	c.ReduceMaxBitsMap["InvE"] += c.ReduceMaxBitsCounter - curNumReduce

	return out
}

func (c *Chip) Ext2Felt(in ExtensionVariable) [4]Variable {
	return in.Value
}

func (c *Chip) DivF(a, b Variable) Variable {
	bInv := c.invF(b)
	x, _, _ := c.MulF(a, bInv)
	return x
}

func (c *Chip) DivE(a, b ExtensionVariable) ExtensionVariable {
	curNumReduce := c.ReduceMaxBitsCounter
	bInv := c.InvE(b)
	retVal := c.MulE(a, bInv)
	c.ReduceMaxBitsMap["DivE"] += c.ReduceMaxBitsCounter - curNumReduce
	return retVal
}

func (c *Chip) NegE(a ExtensionVariable) ExtensionVariable {
	curNumReduce := c.ReduceMaxBitsCounter
	v1 := c.negF(a.Value[0])
	v2 := c.negF(a.Value[1])
	v3 := c.negF(a.Value[2])
	v4 := c.negF(a.Value[3])
	c.ReduceMaxBitsMap["NegE"] += c.ReduceMaxBitsCounter - curNumReduce
	return ExtensionVariable{Value: [4]Variable{v1, v2, v3, v4}}
}

func (c *Chip) ToBinary(in Variable) []frontend.Variable {
	curNumReduce := c.ReduceMaxBitsCounter
	retVal := c.api.ToBinary(c.ReduceSlow(in).Value, 32)
	c.ReduceMaxBitsMap["ToBinary"] += c.ReduceMaxBitsCounter - curNumReduce
	return retVal
}

func (p *Chip) reduceFast(x Variable) Variable {
	if x.NbBits >= uint(252) {
		return Variable{
			Value:  p.reduceWithMaxBits(x.Value, uint64(x.NbBits)),
			NbBits: 31,
		}
	}
	return x
}

func (p *Chip) ReduceSlow(x Variable) Variable {
	if x.NbBits == 31 {
		return x
	}
	return Variable{
		Value:  p.reduceWithMaxBits(x.Value, uint64(x.NbBits)),
		NbBits: 31,
	}
}

func (p *Chip) ReduceF(x Variable) Variable {
	return p.ReduceSlow(x)
}

func (p *Chip) ReduceE(x ExtensionVariable) ExtensionVariable {
	for i := 0; i < 4; i++ {
		x.Value[i] = p.ReduceSlow(x.Value[i])
	}
	return x
}

func (p *Chip) reduceWithMaxBits(x frontend.Variable, maxNbBits uint64) frontend.Variable {
	if maxNbBits <= 31 {
		return x
	}
	result, err := p.api.Compiler().NewHint(ReduceHint, 2, x)
	if err != nil {
		panic(err)
	}
	p.ReduceMaxBitsCounter++

	quotient := result[0]
	remainder := result[1]

	if os.Getenv("RANGE_CHECKER") == "true" {
		p.rangeChecker.Check(quotient, int(maxNbBits-31))
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
		p.rangeChecker.Check(highLimb, 4)
		p.rangeChecker.Check(lowLimb, 27)

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
	} else {
		bits := p.api.ToBinary(remainder, 31)
		p.api.ToBinary(quotient, int(maxNbBits-31))
		lowBits := frontend.Variable(0)
		highBits := frontend.Variable(0)
		for i := 0; i < 27; i++ {
			lowBits = p.api.Add(lowBits, bits[i])
		}
		for i := 27; i < 31; i++ {
			highBits = p.api.Add(highBits, bits[i])
		}
		highBitsIsFour := p.api.IsZero(p.api.Sub(highBits, 4))
		p.api.AssertIsEqual(p.api.Select(highBitsIsFour, lowBits, frontend.Variable(0)), frontend.Variable(0))
	}

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

func InvFHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	a := C.uint(inputs[0].Uint64())
	ainv := C.babybearinv(a)
	results[0].SetUint64(uint64(ainv))
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
