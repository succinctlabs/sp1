package babybear

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

var BabyBearModulus = new(big.Int).SetUint64(2013265921)

type BabyBearParams struct{}

func (fp BabyBearParams) NbLimbs() uint            { return 1 }
func (fp BabyBearParams) BitsPerLimb() uint        { return 32 }
func (fp BabyBearParams) IsPrime() bool            { return true }
func (fp BabyBearParams) Modulus() *big.Int        { return BabyBearModulus }
func (fp BabyBearParams) NumElmsPerBN254Elm() uint { return 8 }

type BabyBearVariable struct {
	value *emulated.Element[BabyBearParams]
}

type BabyBearExtensionVariable struct {
	value [4]*BabyBearVariable
}

type BabyBearChip struct {
	api   frontend.API
	field *emulated.Field[BabyBearParams]
}

func NewBabyBearChip(api frontend.API) *BabyBearChip {
	field, err := emulated.NewField[BabyBearParams](api)
	if err != nil {
		panic(err)
	}
	return &BabyBearChip{
		api:   api,
		field: field,
	}
}

func NewVariable(value int) *BabyBearVariable {
	variable := emulated.ValueOf[BabyBearParams](value)
	return &BabyBearVariable{
		value: &variable,
	}
}

func NewExtensionVariable(value [4]int) *BabyBearExtensionVariable {
	a := NewVariable(value[0])
	b := NewVariable(value[1])
	c := NewVariable(value[2])
	d := NewVariable(value[3])
	return &BabyBearExtensionVariable{value: [4]*BabyBearVariable{a, b, c, d}}
}

func (c *BabyBearChip) Add(a, b *BabyBearVariable) *BabyBearVariable {
	return &BabyBearVariable{
		value: c.field.Add(a.value, b.value),
	}
}

func (c *BabyBearChip) Sub(a, b *BabyBearVariable) *BabyBearVariable {
	return &BabyBearVariable{
		value: c.field.Sub(a.value, b.value),
	}
}

func (c *BabyBearChip) Mul(a, b *BabyBearVariable) *BabyBearVariable {
	return &BabyBearVariable{
		value: c.field.Mul(a.value, b.value),
	}
}

func (c *BabyBearChip) Neg(a *BabyBearVariable) *BabyBearVariable {
	return &BabyBearVariable{
		value: c.field.Neg(a.value),
	}
}

func (c *BabyBearChip) Inv(a *BabyBearVariable) *BabyBearVariable {
	return &BabyBearVariable{
		value: c.field.Inverse(a.value),
	}
}

func (c *BabyBearChip) AssertEq(a, b *BabyBearVariable) {
	c.field.AssertIsEqual(a.value, b.value)
}

func (c *BabyBearChip) AssertNe(a, b *BabyBearVariable) {
	diff := c.field.Sub(a.value, b.value)
	isZero := c.field.IsZero(diff)
	c.api.AssertIsEqual(isZero, frontend.Variable(0))
}

func (c *BabyBearChip) AddExtension(a, b *BabyBearExtensionVariable) *BabyBearExtensionVariable {
	v1 := c.Add(a.value[0], b.value[0])
	v2 := c.Add(a.value[1], b.value[1])
	v3 := c.Add(a.value[2], b.value[2])
	v4 := c.Add(a.value[3], b.value[3])
	return &BabyBearExtensionVariable{value: [4]*BabyBearVariable{v1, v2, v3, v4}}
}

func (c *BabyBearChip) SubExtension(a, b *BabyBearExtensionVariable) *BabyBearExtensionVariable {
	v1 := c.Sub(a.value[0], b.value[0])
	v2 := c.Sub(a.value[1], b.value[1])
	v3 := c.Sub(a.value[2], b.value[2])
	v4 := c.Sub(a.value[3], b.value[3])
	return &BabyBearExtensionVariable{value: [4]*BabyBearVariable{v1, v2, v3, v4}}
}

func (c *BabyBearChip) MulExtension(a, b *BabyBearExtensionVariable) *BabyBearExtensionVariable {
	w := NewVariable(11)
	v := [4]*BabyBearVariable{
		NewVariable(0),
		NewVariable(0),
		NewVariable(0),
		NewVariable(0),
	}

	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			if i+j >= 4 {
				v[i+j-4] = c.Add(v[i+j-4], c.Mul(c.Mul(v[i], v[j]), w))
			} else {
				v[i+j] = c.Add(v[i+j], c.Mul(v[i], v[j]))
			}
		}
	}

	return &BabyBearExtensionVariable{value: v}
}

func (c *BabyBearChip) NegExtension(a *BabyBearExtensionVariable) *BabyBearExtensionVariable {
	v1 := c.Neg(a.value[0])
	v2 := c.Neg(a.value[1])
	v3 := c.Neg(a.value[2])
	v4 := c.Neg(a.value[3])
	return &BabyBearExtensionVariable{value: [4]*BabyBearVariable{v1, v2, v3, v4}}
}

func (c *BabyBearChip) InvExtension(a *BabyBearExtensionVariable) *BabyBearExtensionVariable {
	v := [4]*BabyBearVariable{
		NewVariable(0),
		NewVariable(0),
		NewVariable(0),
		NewVariable(0),
	}
	return &BabyBearExtensionVariable{value: v}
}

func (c *BabyBearChip) AssertEqExtension(a, b *BabyBearExtensionVariable) {
	c.AssertEq(a.value[0], b.value[0])
	c.AssertEq(a.value[1], b.value[1])
	c.AssertEq(a.value[2], b.value[2])
	c.AssertEq(a.value[3], b.value[3])
}

func (c *BabyBearChip) AssertNeExtension(a, b *BabyBearExtensionVariable) {
	v1 := c.field.Sub(a.value[0].value, b.value[0].value)
	v2 := c.field.Sub(a.value[1].value, b.value[1].value)
	v3 := c.field.Sub(a.value[2].value, b.value[2].value)
	v4 := c.field.Sub(a.value[3].value, b.value[3].value)
	isZero1 := c.field.IsZero(v1)
	isZero2 := c.field.IsZero(v2)
	isZero3 := c.field.IsZero(v3)
	isZero4 := c.field.IsZero(v4)
	isZero1AndZero2 := c.api.And(isZero1, isZero2)
	isZero3AndZero4 := c.api.And(isZero3, isZero4)
	isZeroAll := c.api.And(isZero1AndZero2, isZero3AndZero4)
	c.api.AssertIsEqual(isZeroAll, frontend.Variable(0))
}
