package babybear

/*
#cgo LDFLAGS: ./lib/libbabybear.a -ldl
#include "../lib/babybear.h"
*/
import "C"

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/rangecheck"
)

var MODULUS = new(big.Int).SetUint64(2013265921)
var W = new(big.Int).SetUint64(11)

type Params struct{}

func (fp Params) NbLimbs() uint            { return 1 }
func (fp Params) BitsPerLimb() uint        { return 32 }
func (fp Params) IsPrime() bool            { return true }
func (fp Params) Modulus() *big.Int        { return MODULUS }
func (fp Params) NumElmsPerBN254Elm() uint { return 8 }

func init() {
	solver.RegisterHint(InvEHint)
	solver.RegisterHint(ReduceHint)
}

type Variable struct {
	Value *emulated.Element[Params]
}

type ExtensionVariable struct {
	Value [4]*Variable
}

type Chip struct {
	api          frontend.API
	field        *emulated.Field[Params]
	rangeChecker frontend.Rangechecker
}

func NewChip(api frontend.API) *Chip {
	field, err := emulated.NewField[Params](api)
	if err != nil {
		panic(err)
	}
	return &Chip{
		api:          api,
		field:        field,
		rangeChecker: rangecheck.New(api),
	}
}

func NewF(value string) *Variable {
	variable := emulated.ValueOf[Params](value)
	return &Variable{
		Value: &variable,
	}
}

func NewE(value []string) *ExtensionVariable {
	a := NewF(value[0])
	b := NewF(value[1])
	c := NewF(value[2])
	d := NewF(value[3])
	return &ExtensionVariable{Value: [4]*Variable{a, b, c, d}}
}

func Felts2Ext(a, b, c, d *Variable) *ExtensionVariable {
	return &ExtensionVariable{Value: [4]*Variable{a, b, c, d}}
}

func (c *Chip) AddF(a, b *Variable) *Variable {
	return &Variable{
		Value: c.field.Add(a.Value, b.Value),
	}
}

func (c *Chip) SubF(a, b *Variable) *Variable {
	return &Variable{
		Value: c.field.Sub(a.Value, b.Value),
	}
}

func (c *Chip) MulF(a, b *Variable) *Variable {
	return &Variable{
		Value: c.field.MulMod(a.Value, b.Value),
	}
}

func (c *Chip) Neg(a *Variable) *Variable {
	return &Variable{
		Value: c.field.Neg(a.Value),
	}
}

func (c *Chip) Inv(a *Variable) *Variable {
	return &Variable{
		Value: c.field.Inverse(a.Value),
	}
}

func (c *Chip) AssertIsEqualV(a, b *Variable) {
	c.field.AssertIsEqual(a.Value, b.Value)
}

func (c *Chip) AssertIsEqualE(a, b *ExtensionVariable) {
	c.field.AssertIsEqual(c.field.Reduce(a.Value[0].Value), c.field.Reduce(b.Value[0].Value))
	c.field.AssertIsEqual(c.field.Reduce(a.Value[1].Value), c.field.Reduce(b.Value[1].Value))
	c.field.AssertIsEqual(c.field.Reduce(a.Value[2].Value), c.field.Reduce(b.Value[2].Value))
	c.field.AssertIsEqual(c.field.Reduce(a.Value[3].Value), c.field.Reduce(b.Value[3].Value))
}

func (c *Chip) AssertNe(a, b *Variable) {
	diff := c.field.Sub(a.Value, b.Value)
	isZero := c.field.IsZero(diff)
	c.api.AssertIsEqual(isZero, frontend.Variable(0))
}

func (c *Chip) SelectF(cond frontend.Variable, a, b *Variable) *Variable {
	return &Variable{
		Value: c.field.Select(cond, a.Value, b.Value),
	}
}

func (c *Chip) SelectE(cond frontend.Variable, a, b *ExtensionVariable) *ExtensionVariable {
	return &ExtensionVariable{
		Value: [4]*Variable{
			c.SelectF(cond, a.Value[0], b.Value[0]),
			c.SelectF(cond, a.Value[1], b.Value[1]),
			c.SelectF(cond, a.Value[2], b.Value[2]),
			c.SelectF(cond, a.Value[3], b.Value[3]),
		},
	}
}

func (c *Chip) AddEF(a *ExtensionVariable, b *Variable) *ExtensionVariable {
	v1 := c.AddF(a.Value[0], b)
	v2 := c.AddF(a.Value[1], NewF("0"))
	v3 := c.AddF(a.Value[2], NewF("0"))
	v4 := c.AddF(a.Value[3], NewF("0"))
	return &ExtensionVariable{Value: [4]*Variable{v1, v2, v3, v4}}
}

func (c *Chip) AddE(a, b *ExtensionVariable) *ExtensionVariable {
	v1 := c.AddF(a.Value[0], b.Value[0])
	v2 := c.AddF(a.Value[1], b.Value[1])
	v3 := c.AddF(a.Value[2], b.Value[2])
	v4 := c.AddF(a.Value[3], b.Value[3])
	return &ExtensionVariable{Value: [4]*Variable{v1, v2, v3, v4}}
}

func (c *Chip) SubE(a, b *ExtensionVariable) *ExtensionVariable {
	v1 := c.SubF(a.Value[0], b.Value[0])
	v2 := c.SubF(a.Value[1], b.Value[1])
	v3 := c.SubF(a.Value[2], b.Value[2])
	v4 := c.SubF(a.Value[3], b.Value[3])
	return &ExtensionVariable{Value: [4]*Variable{v1, v2, v3, v4}}
}

func (c *Chip) MulE(a, b *ExtensionVariable) *ExtensionVariable {
	a1 := c.field.Reduce(a.Value[0].Value).Limbs[0]
	a2 := c.field.Reduce(a.Value[1].Value).Limbs[0]
	a3 := c.field.Reduce(a.Value[2].Value).Limbs[0]
	a4 := c.field.Reduce(a.Value[3].Value).Limbs[0]

	b1 := c.field.Reduce(b.Value[0].Value).Limbs[0]
	b2 := c.field.Reduce(b.Value[1].Value).Limbs[0]
	b3 := c.field.Reduce(b.Value[2].Value).Limbs[0]
	b4 := c.field.Reduce(b.Value[3].Value).Limbs[0]

	in1 := [4]frontend.Variable{
		a1,
		a2,
		a3,
		a4,
	}
	in2 := [4]frontend.Variable{
		b1,
		b2,
		b3,
		b4,
	}

	v2 := [4]frontend.Variable{
		"0",
		"0",
		"0",
		"0",
	}

	eleven := frontend.Variable("11")
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			if i+j >= 4 {
				v2[i+j-4] = c.api.Add(v2[i+j-4], c.api.Mul(c.api.Mul(in1[i], in2[j]), eleven))
			} else {
				v2[i+j] = c.api.Add(v2[i+j], c.api.Mul(in1[i], in2[j]))
			}
		}
	}

	x := c.ReduceFast(v2[0])
	y := c.ReduceFast(v2[1])
	z := c.ReduceFast(v2[2])
	e := c.ReduceFast(v2[3])

	return &ExtensionVariable{Value: [4]*Variable{x, y, z, e}}
}

func (c *Chip) DivE(a, b *ExtensionVariable) *ExtensionVariable {
	bInv := c.InvE(b)
	return c.MulE(a, bInv)
}

func (c *Chip) NegE(a *ExtensionVariable) *ExtensionVariable {
	v1 := c.Neg(a.Value[0])
	v2 := c.Neg(a.Value[1])
	v3 := c.Neg(a.Value[2])
	v4 := c.Neg(a.Value[3])
	return &ExtensionVariable{Value: [4]*Variable{v1, v2, v3, v4}}
}

func (c *Chip) AssertNeExtension(a, b *ExtensionVariable) {
	v1 := c.field.Sub(a.Value[0].Value, b.Value[0].Value)
	v2 := c.field.Sub(a.Value[1].Value, b.Value[1].Value)
	v3 := c.field.Sub(a.Value[2].Value, b.Value[2].Value)
	v4 := c.field.Sub(a.Value[3].Value, b.Value[3].Value)
	isZero1 := c.field.IsZero(v1)
	isZero2 := c.field.IsZero(v2)
	isZero3 := c.field.IsZero(v3)
	isZero4 := c.field.IsZero(v4)
	isZero1AndZero2 := c.api.And(isZero1, isZero2)
	isZero3AndZero4 := c.api.And(isZero3, isZero4)
	isZeroAll := c.api.And(isZero1AndZero2, isZero3AndZero4)
	c.api.AssertIsEqual(isZeroAll, frontend.Variable(0))
}

func (c *Chip) SelectExtension(cond frontend.Variable, a, b *ExtensionVariable) *ExtensionVariable {
	v1 := c.SelectF(cond, a.Value[0], b.Value[0])
	v2 := c.SelectF(cond, a.Value[1], b.Value[1])
	v3 := c.SelectF(cond, a.Value[2], b.Value[2])
	v4 := c.SelectF(cond, a.Value[3], b.Value[3])
	return &ExtensionVariable{Value: [4]*Variable{v1, v2, v3, v4}}
}

func (c *Chip) SplitIntoBabyBear(in frontend.Variable) [8]Variable {
	bits := c.api.ToBinary(in)
	var result [8]frontend.Variable
	for i := 0; i < 8; i++ {
		result[i] = frontend.Variable(0)
	}

	for i := 0; i < 8; i++ {
		for j := 0; j < 8; j++ {
			if i*8+j <= 254 {
				result[i] = c.api.Add(result[i], c.api.Mul(bits[i*8+j], frontend.Variable(1<<j)))
			}
		}
	}

	var result2 [8]Variable
	for i := 0; i < 8; i++ {
		result2[i] = Variable{Value: c.field.NewElement(result[i])}
	}

	return result2
}

func (c *Chip) ToBinary(in *Variable) []frontend.Variable {
	return c.field.ToBits(c.field.Reduce(in.Value))
}

func (c *Chip) PrintF(in *Variable) {
	c.api.Println(c.field.Reduce(in.Value).Limbs[0])
}

func (c *Chip) PrintE(in *ExtensionVariable) {
	c.PrintF(in.Value[0])
	c.PrintF(in.Value[1])
	c.PrintF(in.Value[2])
	c.PrintF(in.Value[3])
}

func (c *Chip) InvE(in *ExtensionVariable) *ExtensionVariable {
	x := c.field.Reduce(in.Value[0].Value)
	y := c.field.Reduce(in.Value[1].Value)
	z := c.field.Reduce(in.Value[2].Value)
	l := c.field.Reduce(in.Value[3].Value)

	result, err := c.api.Compiler().NewHint(InvEHint, 4, x.Limbs[0], y.Limbs[0], z.Limbs[0], l.Limbs[0])
	if err != nil {
		panic(err)
	}

	xinv := Variable{Value: c.field.NewElement(result[0])}
	yinv := Variable{Value: c.field.NewElement(result[1])}
	zinv := Variable{Value: c.field.NewElement(result[2])}
	linv := Variable{Value: c.field.NewElement(result[3])}
	out := ExtensionVariable{Value: [4]*Variable{&xinv, &yinv, &zinv, &linv}}

	product := c.MulE(in, &out)
	c.AssertIsEqualE(product, NewE([]string{"1", "0", "0", "0"}))

	return &out
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

func (c *Chip) Ext2Felt(in *ExtensionVariable) [4]*Variable {
	return in.Value
}

func (c *Chip) Reduce(in *Variable) *Variable {
	return &Variable{
		Value: c.field.Reduce(in.Value),
	}
}

func (p *Chip) ReduceFast(x frontend.Variable) *Variable {
	return p.ReduceWithMaxBits(x, uint64(80))
}

func (p *Chip) ReduceWithMaxBits(x frontend.Variable, maxNbBits uint64) *Variable {
	result, err := p.api.Compiler().NewHint(ReduceHint, 2, x)
	if err != nil {
		panic(err)
	}

	quotient := result[0]
	p.rangeChecker.Check(quotient, int(maxNbBits))

	p.rangeChecker.Check(result[1], int(maxNbBits))
	remainder := p.field.NewElement(result[1])

	p.api.AssertIsEqual(x, p.api.Add(p.api.Mul(quotient, MODULUS), result[1]))

	return &Variable{
		Value: remainder,
	}
}

// The hint used to compute Reduce.
func ReduceHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 1 {
		panic("ReduceHint expects 1 input operand")
	}
	input := inputs[0]
	quotient := new(big.Int).Div(input, MODULUS)
	remainder := new(big.Int).Rem(input, MODULUS)
	results[0] = quotient
	results[1] = remainder
	return nil
}
