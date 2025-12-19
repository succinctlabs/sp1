use super::{BinomialExtensionField, BinomiallyExtendable, HasTwoAdicBionmialExtension};
use crate::{AbstractExtensionField, AbstractField, Field};

pub type Complex<AF> = BinomialExtensionField<AF, 2>;

/// A field for which `p = 3 (mod 4)`. Equivalently, `-1` is not a square,
/// so the complex extension can be defined `F[X]/(X^2+1)`.
pub trait ComplexExtendable: Field {
    /// The two-adicity of `p+1`, the order of the circle group.
    const CIRCLE_TWO_ADICITY: usize;

    fn complex_generator() -> Complex<Self>;

    fn circle_two_adic_generator(bits: usize) -> Complex<Self>;
}

impl<F: ComplexExtendable> BinomiallyExtendable<2> for F {
    fn w() -> Self {
        F::neg_one()
    }
    fn dth_root() -> Self {
        // since `p = 3 (mod 4)`, `(p-1)/2` is always odd,
        // so `(-1)^((p-1)/2) = -1`
        F::neg_one()
    }
    fn ext_generator() -> [Self; 2] {
        F::complex_generator().value
    }
}

/// Convenience methods for complex extensions
impl<AF: AbstractField> Complex<AF> {
    pub const fn new(real: AF, imag: AF) -> Self {
        Self {
            value: [real, imag],
        }
    }
    pub fn new_real(real: AF) -> Self {
        Self::new(real, AF::zero())
    }
    pub fn new_imag(imag: AF) -> Self {
        Self::new(AF::zero(), imag)
    }
    pub fn real(&self) -> AF {
        self.value[0].clone()
    }
    pub fn imag(&self) -> AF {
        self.value[1].clone()
    }
    pub fn conjugate(&self) -> Self {
        Self::new(self.real(), self.imag().neg())
    }
    pub fn norm(&self) -> AF {
        self.real().square() + self.imag().square()
    }
    pub fn to_array(&self) -> [AF; 2] {
        self.value.clone()
    }
    // Sometimes we want to rotate over an extension that's not necessarily ComplexExtendable,
    // but still on the circle.
    pub fn rotate<Ext: AbstractExtensionField<AF>>(&self, rhs: Complex<Ext>) -> Complex<Ext> {
        Complex::<Ext>::new(
            rhs.real() * self.real() - rhs.imag() * self.imag(),
            rhs.imag() * self.real() + rhs.real() * self.imag(),
        )
    }
}

/// The complex extension of this field has a binomial extension.
pub trait HasComplexBinomialExtension<const D: usize>: ComplexExtendable {
    fn w() -> Complex<Self>;
    fn dth_root() -> Complex<Self>;
    fn ext_generator() -> [Complex<Self>; D];
}

impl<F, const D: usize> BinomiallyExtendable<D> for Complex<F>
where
    F: HasComplexBinomialExtension<D>,
{
    fn w() -> Self {
        <F as HasComplexBinomialExtension<D>>::w()
    }
    fn dth_root() -> Self {
        <F as HasComplexBinomialExtension<D>>::dth_root()
    }
    fn ext_generator() -> [Self; D] {
        <F as HasComplexBinomialExtension<D>>::ext_generator()
    }
}

/// The complex extension of this field has a two-adic binomial extension.
pub trait HasTwoAdicComplexBinomialExtension<const D: usize>:
    HasComplexBinomialExtension<D>
{
    const COMPLEX_EXT_TWO_ADICITY: usize;
    fn complex_ext_two_adic_generator(bits: usize) -> [Complex<Self>; D];
}

impl<F, const D: usize> HasTwoAdicBionmialExtension<D> for Complex<F>
where
    F: HasTwoAdicComplexBinomialExtension<D>,
{
    const EXT_TWO_ADICITY: usize = F::COMPLEX_EXT_TWO_ADICITY;

    fn ext_two_adic_generator(bits: usize) -> [Self; D] {
        F::complex_ext_two_adic_generator(bits)
    }
}
