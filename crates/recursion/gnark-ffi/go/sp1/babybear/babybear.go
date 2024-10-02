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
var modulus_sub_1 = new(big.Int).SetUint64(2013265920)

// bound = 2^120: we'll keep an invariant that all direct inputs and final outputs of invocations of BabyBear API has UpperBound less than bound
var bound = new(big.Int).Exp(new(big.Int).SetUint64(2), new(big.Int).SetUint64(120), new(big.Int).SetUint64(0))

// bound_reduce = 2^250: we'll keep an invariant that all invocations of reduceFast and ReduceSlow has UpperBound less than bound_reduce
var bound_reduce = new(big.Int).Exp(new(big.Int).SetUint64(2), new(big.Int).SetUint64(250), new(big.Int).SetUint64(0))

func init() {
	// These functions must be public so Gnark's hint system can access them.
	solver.RegisterHint(InvFHint)
	solver.RegisterHint(InvEHint)
	solver.RegisterHint(ReduceHint)
	solver.RegisterHint(SplitLimbsHint)
}

// UpperBound represents the known upper bound of the Value (0 <= Value <= UpperBound)
type Variable struct {
	Value      frontend.Variable
	UpperBound *big.Int
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
		Value:      frontend.Variable("0"),
		UpperBound: new(big.Int).SetUint64(0),
	}
}

func One() Variable {
	return Variable{
		Value:      frontend.Variable("1"),
		UpperBound: new(big.Int).SetUint64(1),
	}
}

func NewFConst(value string) Variable {
	int_value, success := new(big.Int).SetString(value, 10)
	if !success || int_value.BitLen() > 32 {
		panic("string to int conversion failed")
	}
	return Variable{
		Value:      frontend.Variable(value),
		UpperBound: int_value,
	}
}

func NewF(value string) Variable {
	return Variable{
		Value:      frontend.Variable(value),
		UpperBound: new(big.Int).SetUint64(uint64(math.Pow(2, 32))),
	}
}

func NewE(value []string) ExtensionVariable {
	a := NewF(value[0])
	b := NewF(value[1])
	c := NewF(value[2])
	d := NewF(value[3])
	return ExtensionVariable{Value: [4]Variable{a, b, c, d}}
}

func NewEConst(value []string) ExtensionVariable {
	a := NewFConst(value[0])
	b := NewFConst(value[1])
	c := NewFConst(value[2])
	d := NewFConst(value[3])
	return ExtensionVariable{Value: [4]Variable{a, b, c, d}}
}

// we compile-time assert that the variable has UpperBound less than 2^120
func InvariantCheckF(a Variable) {
	if a.UpperBound.Cmp(bound) != -1 {
		panic("InvariantCheckF failure")
	}
}

// we compile-time assert that each Variable of the ExtensionVariable has UpperBound less than 2^120
func InvariantCheckE(a ExtensionVariable) {
	for i := 0; i < 4; i++ {
		InvariantCheckF(a.Value[i])
	}
}

// we compile-time assert that the Variable being reduced has UpperBound less than 2^250
func InvariantCheckReduce(a Variable) {
	if a.UpperBound.Cmp(bound_reduce) != -1 {
		panic("InvariantCheckReduce failure")
	}
}

func Felts2Ext(a, b, c, d Variable) ExtensionVariable {
	return ExtensionVariable{Value: [4]Variable{a, b, c, d}}
}

func (c *Chip) AddF(a, b Variable, forceReduce ...bool) Variable {
	// a.Value <= a.UpperBound, b.Value <= b.UpperBound implies
	// a.Value + b.Value <= a.UpperBound + b.UpperBound
	result := Variable{
		Value:      c.api.Add(a.Value, b.Value),
		UpperBound: new(big.Int).Add(a.UpperBound, b.UpperBound),
	}
	// we assert that the result has upper bound less than 2^250
	InvariantCheckReduce(result)
	// if we explicitly send over false, we skip the call to reduceFast
	if len(forceReduce) > 0 && !forceReduce[0] {
		return result
	}
	InvariantCheckF(a)
	InvariantCheckF(b)
	return c.reduceFast(result)
}

func (c *Chip) SubF(a, b Variable) Variable {
	InvariantCheckF(a)
	InvariantCheckF(b)
	negB := c.negF(b)
	return c.AddF(a, negB)
}

func (c *Chip) MulF(a, b Variable, forceReduce ...bool) Variable {
	// a.Value <= a.UpperBound, b.Value <= b.UpperBound implies
	// a.Value * b.Value <= a.UpperBound * b.UpperBound
	result := Variable{
		Value:      c.api.Mul(a.Value, b.Value),
		UpperBound: new(big.Int).Mul(a.UpperBound, b.UpperBound),
	}
	// we assert that the result has upper bound less than 2^250
	InvariantCheckReduce(result)
	// if we explicitly send over false, we skip the call to reduceFast
	if len(forceReduce) > 0 && !forceReduce[0] {
		return result
	}
	InvariantCheckF(a)
	InvariantCheckF(b)
	return c.reduceFast(result)
}

func (c *Chip) MulFConst(a Variable, b int, forceReduce ...bool) Variable {
	// a.Value <= a.UpperBound implies
	// a.Value * b <= a.UpperBound * b
	result := Variable{
		Value:      c.api.Mul(a.Value, b),
		UpperBound: new(big.Int).Mul(a.UpperBound, new(big.Int).SetUint64(uint64(b))),
	}
	// we assert that the result has upper bound less than 2^250
	InvariantCheckReduce(result)
	// if we explicitly send over false, we skip the call to reduceFast
	if len(forceReduce) > 0 && !forceReduce[0] {
		return result
	}
	InvariantCheckF(a)
	return c.reduceFast(result)
}

func (c *Chip) negF(a Variable) Variable {
	// 0 <= a.Value <= a.UpperBound implies
	// 0 <= a.Value <= liftedModulus, so 0 <= liftedModulus - a.Value <= liftedModulus
	divisor := new(big.Int).Div(a.UpperBound, modulus)
	divisorPlusOne := new(big.Int).Add(divisor, big.NewInt(1))
	liftedModulus := new(big.Int).Mul(divisorPlusOne, modulus)
	InvariantCheckF(a)
	return c.reduceFast(Variable{
		Value:      c.api.Sub(liftedModulus, a.Value),
		UpperBound: liftedModulus,
	})
}

func (c *Chip) invF(in Variable) Variable {
	InvariantCheckF(in)
	result, err := c.api.Compiler().NewHint(InvFHint, 1, in.Value)
	if err != nil {
		panic(err)
	}

	xinv := Variable{
		Value:      result[0],
		UpperBound: new(big.Int).SetUint64(2147483648),
	}
	if os.Getenv("GROTH16") != "1" {
		c.RangeChecker.Check(result[0], 31)
	} else {
		c.api.ToBinary(result[0], 31)
	}
	product := c.MulF(in, xinv)
	c.AssertIsEqualF(product, NewFConst("1"))

	// UpperBound is 2^31, so the invariant holds
	return xinv
}

func (c *Chip) DivF(a, b Variable) Variable {
	InvariantCheckF(a)
	InvariantCheckF(b)
	bInv := c.invF(b)
	return c.MulF(a, bInv)
}

func (c *Chip) AssertIsEqualF(a, b Variable) {
	InvariantCheckF(a)
	InvariantCheckF(b)
	a2 := c.ReduceSlow(a)
	b2 := c.ReduceSlow(b)
	c.api.AssertIsEqual(a2.Value, b2.Value)
}

func (c *Chip) AssertNotEqualF(a, b Variable) {
	InvariantCheckF(a)
	InvariantCheckF(b)
	a2 := c.ReduceSlow(a)
	b2 := c.ReduceSlow(b)
	c.api.AssertIsDifferent(a2.Value, b2.Value)
}

func (c *Chip) AssertIsEqualE(a, b ExtensionVariable) {
	InvariantCheckE(a)
	InvariantCheckE(b)
	c.AssertIsEqualF(a.Value[0], b.Value[0])
	c.AssertIsEqualF(a.Value[1], b.Value[1])
	c.AssertIsEqualF(a.Value[2], b.Value[2])
	c.AssertIsEqualF(a.Value[3], b.Value[3])
}

func (c *Chip) SelectF(cond frontend.Variable, a, b Variable) Variable {
	InvariantCheckF(a)
	InvariantCheckF(b)
	var UpperBound *big.Int
	// take maximum of a.UpperBound and b.UpperBound
	if a.UpperBound.Cmp(b.UpperBound) == -1 {
		UpperBound = b.UpperBound
	} else {
		UpperBound = a.UpperBound
	}
	return Variable{
		Value:      c.api.Select(cond, a.Value, b.Value),
		UpperBound: UpperBound,
	}
}

func (c *Chip) SelectE(cond frontend.Variable, a, b ExtensionVariable) ExtensionVariable {
	InvariantCheckE(a)
	InvariantCheckE(b)
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
	InvariantCheckE(a)
	InvariantCheckF(b)
	v1 := c.AddF(a.Value[0], b)
	return ExtensionVariable{Value: [4]Variable{v1, a.Value[1], a.Value[2], a.Value[3]}}
}

func (c *Chip) AddE(a, b ExtensionVariable) ExtensionVariable {
	InvariantCheckE(a)
	InvariantCheckE(b)
	v1 := c.AddF(a.Value[0], b.Value[0])
	v2 := c.AddF(a.Value[1], b.Value[1])
	v3 := c.AddF(a.Value[2], b.Value[2])
	v4 := c.AddF(a.Value[3], b.Value[3])
	return ExtensionVariable{Value: [4]Variable{v1, v2, v3, v4}}
}

func (c *Chip) SubE(a, b ExtensionVariable) ExtensionVariable {
	InvariantCheckE(a)
	InvariantCheckE(b)
	v1 := c.SubF(a.Value[0], b.Value[0])
	v2 := c.SubF(a.Value[1], b.Value[1])
	v3 := c.SubF(a.Value[2], b.Value[2])
	v4 := c.SubF(a.Value[3], b.Value[3])
	return ExtensionVariable{Value: [4]Variable{v1, v2, v3, v4}}
}

func (c *Chip) SubEF(a ExtensionVariable, b Variable) ExtensionVariable {
	InvariantCheckE(a)
	InvariantCheckF(b)
	v1 := c.SubF(a.Value[0], b)
	return ExtensionVariable{Value: [4]Variable{v1, a.Value[1], a.Value[2], a.Value[3]}}
}

func (c *Chip) MulE(a, b ExtensionVariable) ExtensionVariable {
	// we check that a, b has UpperBound less than 2^120
	InvariantCheckE(a)
	InvariantCheckE(b)
	v2 := [4]Variable{
		Zero(),
		Zero(),
		Zero(),
		Zero(),
	}

	// each v2[idx] will be at most 2^120 * 2^120 * 4 * 11 < 2^250, so we delay the reduceFast
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			if i+j >= 4 {
				v2[i+j-4] = c.AddF(v2[i+j-4], c.MulFConst(c.MulF(a.Value[i], b.Value[j], false), 11, false), false)
			} else {
				v2[i+j] = c.AddF(v2[i+j], c.MulF(a.Value[i], b.Value[j], false), false)
			}
		}
	}

	// we invoke reduceFast at the end to assure that each Variable has UpperBound less than 2^120
	v2[0] = c.reduceFast(v2[0])
	v2[1] = c.reduceFast(v2[1])
	v2[2] = c.reduceFast(v2[2])
	v2[3] = c.reduceFast(v2[3])
	return ExtensionVariable{Value: v2}
}

func (c *Chip) MulEF(a ExtensionVariable, b Variable) ExtensionVariable {
	InvariantCheckE(a)
	InvariantCheckF(b)
	v1 := c.MulF(a.Value[0], b)
	v2 := c.MulF(a.Value[1], b)
	v3 := c.MulF(a.Value[2], b)
	v4 := c.MulF(a.Value[3], b)
	return ExtensionVariable{Value: [4]Variable{v1, v2, v3, v4}}
}

func (c *Chip) InvE(in ExtensionVariable) ExtensionVariable {
	InvariantCheckE(in)
	result, err := c.api.Compiler().NewHint(InvEHint, 4, in.Value[0].Value, in.Value[1].Value, in.Value[2].Value, in.Value[3].Value)
	if err != nil {
		panic(err)
	}

	xinv := Variable{Value: result[0], UpperBound: new(big.Int).SetUint64(2147483648)}
	yinv := Variable{Value: result[1], UpperBound: new(big.Int).SetUint64(2147483648)}
	zinv := Variable{Value: result[2], UpperBound: new(big.Int).SetUint64(2147483648)}
	linv := Variable{Value: result[3], UpperBound: new(big.Int).SetUint64(2147483648)}
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
	c.AssertIsEqualE(product, NewEConst([]string{"1", "0", "0", "0"}))

	// UpperBound is 2^31, so the invariant holds
	return out
}

func (c *Chip) Ext2Felt(in ExtensionVariable) [4]Variable {
	return in.Value
}

func (c *Chip) DivE(a, b ExtensionVariable) ExtensionVariable {
	InvariantCheckE(a)
	InvariantCheckE(b)
	bInv := c.InvE(b)
	return c.MulE(a, bInv)
}

func (c *Chip) DivEF(a ExtensionVariable, b Variable) ExtensionVariable {
	InvariantCheckE(a)
	InvariantCheckF(b)
	bInv := c.invF(b)
	return c.MulEF(a, bInv)
}

func (c *Chip) NegE(a ExtensionVariable) ExtensionVariable {
	InvariantCheckE(a)
	v1 := c.negF(a.Value[0])
	v2 := c.negF(a.Value[1])
	v3 := c.negF(a.Value[2])
	v4 := c.negF(a.Value[3])
	return ExtensionVariable{Value: [4]Variable{v1, v2, v3, v4}}
}

func (c *Chip) ToBinary(in Variable) []frontend.Variable {
	return c.api.ToBinary(c.ReduceSlow(in).Value, 31)
}

func (p *Chip) reduceFast(x Variable) Variable {
	// check the variable being reduced has UpperBound less than 2^250, so BN254 overflow doesn't occur
	InvariantCheckReduce(x)
	// if x >= 2^119, we reduce x modulo BabyBear
	// 0 <= remainder <= p - 1, so we choose UpperBound = p - 1
	if x.UpperBound.BitLen() >= 120 {
		return Variable{
			Value:      p.reduceWithMaxBits(x.Value, uint64(x.UpperBound.BitLen())),
			UpperBound: modulus_sub_1,
		}
	}
	return x
}

// ReduceSlow is guaranteed to return x fully reduced to BabyBear range
func (p *Chip) ReduceSlow(x Variable) Variable {
	// check the variable being reduced has UpperBound less than 2^250, so BN254 overflow doesn't occur
	InvariantCheckReduce(x)
	// if x.UpperBound < modulus, this means 0 <= x.Value <= x.UpperBound < modulus
	// therefore, no need to reduce x
	if x.UpperBound.Cmp(modulus) == -1 {
		return x
	}
	// 0 <= remainder <= p - 1, so we choose UpperBound = p - 1
	return Variable{
		Value:      p.reduceWithMaxBits(x.Value, uint64(x.UpperBound.BitLen())),
		UpperBound: modulus_sub_1,
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

	if os.Getenv("GROTH16") != "1" {
		p.RangeChecker.Check(quotient, int(maxNbBits-30))
	} else {
		p.api.ToBinary(quotient, int(maxNbBits-30))
	}

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
		p.api.Mul(
			shouldCheck,
			lowLimb,
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
	InvariantCheckE(x)
	for i := 0; i < 4; i++ {
		x.Value[i] = p.ReduceSlow(x.Value[i])
	}
	return x
}

func InvFHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	a := C.uint(new(big.Int).Mod(inputs[0], modulus).Uint64())
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
	a := C.uint(new(big.Int).Mod(inputs[0], modulus).Uint64())
	b := C.uint(new(big.Int).Mod(inputs[1], modulus).Uint64())
	c := C.uint(new(big.Int).Mod(inputs[2], modulus).Uint64())
	d := C.uint(new(big.Int).Mod(inputs[3], modulus).Uint64())
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
