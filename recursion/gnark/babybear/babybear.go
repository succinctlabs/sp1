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
	value [4]*emulated.Element[BabyBearParams]
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

func New()

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

func (c *BabyBearChip) Neg(a, b *BabyBearVariable) *BabyBearVariable {
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
	v1 := c.field.Add(a.value[0], b.value[0])
	v2 := c.field.Add(a.value[1], b.value[1])
	v3 := c.field.Add(a.value[2], b.value[2])
	v4 := c.field.Add(a.value[3], b.value[3])
	return &BabyBearExtensionVariable{value: [4]*emulated.Element[BabyBearParams]{v1, v2, v3, v4}}
}

func (c *BabyBearChip) SubExtension(a, b *BabyBearExtensionVariable) *BabyBearExtensionVariable {
	v1 := c.field.Sub(a.value[0], b.value[0])
	v2 := c.field.Sub(a.value[1], b.value[1])
	v3 := c.field.Sub(a.value[2], b.value[2])
	v4 := c.field.Sub(a.value[3], b.value[3])
	return &BabyBearExtensionVariable{value: [4]*emulated.Element[BabyBearParams]{v1, v2, v3, v4}}
}

func (c *BabyBearChip) MulExtension(a, b *BabyBearExtensionVariable) *BabyBearExtensionVariable {
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {

		}
	}

	v1 := c.field.Mul(a.value[0], b.value[0])
	v2 := c.field.Mul(a.value[1], b.value[1])
	v3 := c.field.Mul(a.value[2], b.value[2])
	v4 := c.field.Mul(a.value[3], b.value[3])
	return &BabyBearExtensionVariable{value: [4]*emulated.Element[BabyBearParams]{v1, v2, v3, v4}}
}

func (c *BabyBearChip) NegExtension(a *BabyBearExtensionVariable) *BabyBearExtensionVariable {
	v1 := c.field.Neg(a.value[0])
	v2 := c.field.Neg(a.value[1])
	v3 := c.field.Neg(a.value[2])
	v4 := c.field.Neg(a.value[3])
	return &BabyBearExtensionVariable{value: [4]*emulated.Element[BabyBearParams]{v1, v2, v3, v4}}
}
