use super::ECDSACurve;

use elliptic_curve::{
    ops::{Invert, Reduce},
    scalar::{FromUintUnchecked, IsHigh},
    FieldBytes, ScalarPrimitive,
};

use elliptic_curve::{
    ff::{Field, PrimeField},
    rand_core::RngCore,
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::DefaultIsZeroes,
};

use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use std::{
    iter::{Product, Sum},
    ops::ShrAssign,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Scalar<C: ECDSACurve>(pub(crate) C::ScalarImpl);

impl<C: ECDSACurve> Field for Scalar<C> {
    const ONE: Self = Scalar(C::ScalarImpl::ONE);
    const ZERO: Self = Scalar(C::ScalarImpl::ZERO);

    fn random(rng: impl RngCore) -> Self {
        Scalar(C::ScalarImpl::random(rng))
    }

    fn double(&self) -> Self {
        Scalar(self.0.double())
    }

    fn invert(&self) -> CtOption<Self> {
        <C::ScalarImpl as Field>::invert(&self.0).map(Scalar)
    }

    fn is_zero(&self) -> Choice {
        self.0.is_zero()
    }

    fn square(&self) -> Self {
        Scalar(self.0.square())
    }

    fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        let (c, result) = C::ScalarImpl::sqrt_ratio(&num.0, &div.0);

        (c, Scalar(result))
    }
}

impl<C: ECDSACurve> PrimeField for Scalar<C> {
    type Repr = FieldBytes<C>;

    /// Modulus of the field written as a string for debugging purposes.
    ///
    /// The encoding of the modulus is implementation-specific. Generic users of the
    /// `PrimeField` trait should treat this string as opaque.
    const MODULUS: &'static str = C::ScalarImpl::MODULUS;

    /// How many bits are needed to represent an element of this field.
    const NUM_BITS: u32 = C::ScalarImpl::NUM_BITS;

    /// How many bits of information can be reliably stored in the field element.
    ///
    /// This is usually `Self::NUM_BITS - 1`.
    const CAPACITY: u32 = C::ScalarImpl::CAPACITY;

    /// Inverse of $2$ in the field.
    const TWO_INV: Self = Scalar(C::ScalarImpl::TWO_INV);

    /// A fixed multiplicative generator of `modulus - 1` order. This element must also be
    /// a quadratic nonresidue.
    ///
    /// It can be calculated using [SageMath] as `GF(modulus).primitive_element()`.
    ///
    /// Implementations of this trait MUST ensure that this is the generator used to
    /// derive `Self::ROOT_OF_UNITY`.
    ///
    /// [SageMath]: https://www.sagemath.org/
    const MULTIPLICATIVE_GENERATOR: Self = Scalar(C::ScalarImpl::MULTIPLICATIVE_GENERATOR);

    /// An integer `s` satisfying the equation `2^s * t = modulus - 1` with `t` odd.
    ///
    /// This is the number of leading zero bits in the little-endian bit representation of
    /// `modulus - 1`.
    const S: u32 = C::ScalarImpl::S;

    /// The `2^s` root of unity.
    ///
    /// It can be calculated by exponentiating `Self::MULTIPLICATIVE_GENERATOR` by `t`,
    /// where `t = (modulus - 1) >> Self::S`.
    const ROOT_OF_UNITY: Self = Scalar(C::ScalarImpl::ROOT_OF_UNITY);

    /// Inverse of [`Self::ROOT_OF_UNITY`].
    const ROOT_OF_UNITY_INV: Self = Scalar(C::ScalarImpl::ROOT_OF_UNITY_INV);

    /// Generator of the `t-order` multiplicative subgroup.
    ///
    /// It can be calculated by exponentiating [`Self::MULTIPLICATIVE_GENERATOR`] by `2^s`,
    /// where `s` is [`Self::S`].
    const DELTA: Self = Scalar(C::ScalarImpl::DELTA);

    fn from_repr(repr: Self::Repr) -> CtOption<Self> {
        C::ScalarImpl::from_repr(repr).map(Scalar)
    }

    fn to_repr(&self) -> Self::Repr {
        self.0.to_repr()
    }

    fn is_odd(&self) -> Choice {
        self.0.is_odd()
    }
}

impl<C: ECDSACurve> From<u64> for Scalar<C> {
    fn from(v: u64) -> Self {
        Scalar(C::ScalarImpl::from(v))
    }
}

impl<C: ECDSACurve> Add<Scalar<C>> for Scalar<C> {
    type Output = Scalar<C>;

    fn add(self, rhs: Scalar<C>) -> Self::Output {
        Scalar(self.0.add(&rhs.0))
    }
}

impl<C: ECDSACurve> Add<&Scalar<C>> for Scalar<C> {
    type Output = Scalar<C>;

    fn add(self, rhs: &Scalar<C>) -> Self::Output {
        Scalar(self.0.add(&rhs.0))
    }
}

impl<C: ECDSACurve> AddAssign<Scalar<C>> for Scalar<C> {
    fn add_assign(&mut self, rhs: Scalar<C>) {
        self.0.add_assign(&rhs.0);
    }
}

impl<C: ECDSACurve> AddAssign<&Scalar<C>> for Scalar<C> {
    fn add_assign(&mut self, rhs: &Scalar<C>) {
        self.0.add_assign(&rhs.0);
    }
}

impl<C: ECDSACurve> Sub<Scalar<C>> for Scalar<C> {
    type Output = Scalar<C>;

    fn sub(self, rhs: Scalar<C>) -> Self::Output {
        Scalar(self.0.sub(&rhs.0))
    }
}

impl<C: ECDSACurve> Sub<&Scalar<C>> for Scalar<C> {
    type Output = Scalar<C>;

    fn sub(self, rhs: &Scalar<C>) -> Self::Output {
        Scalar(self.0.sub(&rhs.0))
    }
}

impl<C: ECDSACurve> SubAssign<Scalar<C>> for Scalar<C> {
    fn sub_assign(&mut self, rhs: Scalar<C>) {
        self.0.sub_assign(&rhs.0);
    }
}

impl<C: ECDSACurve> SubAssign<&Scalar<C>> for Scalar<C> {
    fn sub_assign(&mut self, rhs: &Scalar<C>) {
        self.0.sub_assign(&rhs.0);
    }
}

impl<C: ECDSACurve> Mul<Scalar<C>> for Scalar<C> {
    type Output = Scalar<C>;

    fn mul(self, rhs: Scalar<C>) -> Self::Output {
        Scalar(self.0.mul(&rhs.0))
    }
}

impl<C: ECDSACurve> Mul<&Scalar<C>> for Scalar<C> {
    type Output = Scalar<C>;

    fn mul(self, rhs: &Scalar<C>) -> Self::Output {
        Scalar(self.0.mul(&rhs.0))
    }
}

impl<C: ECDSACurve> MulAssign<Scalar<C>> for Scalar<C> {
    fn mul_assign(&mut self, rhs: Scalar<C>) {
        self.0.mul_assign(&rhs.0);
    }
}

impl<C: ECDSACurve> MulAssign<&Scalar<C>> for Scalar<C> {
    fn mul_assign(&mut self, rhs: &Scalar<C>) {
        self.0.mul_assign(&rhs.0);
    }
}

impl<C: ECDSACurve> Neg for Scalar<C> {
    type Output = Scalar<C>;

    fn neg(self) -> Self::Output {
        Scalar(self.0.neg())
    }
}

impl<C: ECDSACurve> Product<Scalar<C>> for Scalar<C> {
    fn product<I: IntoIterator<Item = Scalar<C>>>(iter: I) -> Self {
        Scalar(C::ScalarImpl::product(iter.into_iter().map(|s| s.0)))
    }
}

impl<'a, C: ECDSACurve> Product<&'a Scalar<C>> for Scalar<C> {
    fn product<I: IntoIterator<Item = &'a Scalar<C>>>(iter: I) -> Self {
        Scalar(C::ScalarImpl::product(iter.into_iter().map(|s| s.0)))
    }
}

impl<C: ECDSACurve> Sum<Scalar<C>> for Scalar<C> {
    fn sum<I: IntoIterator<Item = Scalar<C>>>(iter: I) -> Self {
        Scalar(C::ScalarImpl::sum(iter.into_iter().map(|s| s.0)))
    }
}

impl<'a, C: ECDSACurve> Sum<&'a Scalar<C>> for Scalar<C> {
    fn sum<I: IntoIterator<Item = &'a Scalar<C>>>(iter: I) -> Self {
        Scalar(C::ScalarImpl::sum(iter.into_iter().map(|s| s.0)))
    }
}

impl<C: ECDSACurve> ConstantTimeEq for Scalar<C> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<C: ECDSACurve> ConditionallySelectable for Scalar<C> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Scalar(C::ScalarImpl::conditional_select(&a.0, &b.0, choice))
    }
}

impl<C: ECDSACurve> IsHigh for Scalar<C> {
    fn is_high(&self) -> Choice {
        self.0.is_high()
    }
}

impl<C: ECDSACurve> PartialOrd for Scalar<C> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl<C: ECDSACurve> Invert for Scalar<C> {
    type Output = CtOption<Self>;

    fn invert(&self) -> Self::Output {
        <C::ScalarImpl as Invert>::invert(&self.0).map(Scalar)
    }
}

impl<C: ECDSACurve> FromUintUnchecked for Scalar<C> {
    type Uint = <C::ScalarImpl as FromUintUnchecked>::Uint;

    fn from_uint_unchecked(uint: Self::Uint) -> Self {
        Scalar(C::ScalarImpl::from_uint_unchecked(uint))
    }
}

impl<C: ECDSACurve> Reduce<C::Uint> for Scalar<C> {
    type Bytes = <C::ScalarImpl as Reduce<C::Uint>>::Bytes;

    fn reduce(uint: C::Uint) -> Self {
        Scalar(C::ScalarImpl::reduce(uint))
    }

    fn reduce_bytes(bytes: &Self::Bytes) -> Self {
        Scalar(C::ScalarImpl::reduce_bytes(bytes))
    }
}

impl<C: ECDSACurve> ShrAssign<usize> for Scalar<C> {
    fn shr_assign(&mut self, rhs: usize) {
        self.0.shr_assign(rhs);
    }
}

impl<C: ECDSACurve> DefaultIsZeroes for Scalar<C> {}

impl<C: ECDSACurve> From<ScalarPrimitive<C>> for Scalar<C> {
    fn from(scalar: ScalarPrimitive<C>) -> Self {
        Self::reduce(*scalar.as_uint())
    }
}

impl<C: ECDSACurve> From<Scalar<C>> for ScalarPrimitive<C> {
    fn from(scalar: Scalar<C>) -> Self {
        ScalarPrimitive::from_uint_unchecked(scalar.0.into())
    }
}

impl<C: ECDSACurve> AsRef<Scalar<C>> for Scalar<C> {
    fn as_ref(&self) -> &Scalar<C> {
        self
    }
}

impl<C: ECDSACurve> From<Scalar<C>> for FieldBytes<C> {
    fn from(scalar: Scalar<C>) -> Self {
        scalar.0.into()
    }
}

impl<C: ECDSACurve> From<FieldBytes<C>> for Scalar<C> {
    fn from(bytes: FieldBytes<C>) -> Self {
        Scalar(C::ScalarImpl::from_repr(bytes).unwrap())
    }
}
