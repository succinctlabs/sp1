use super::{AffinePoint, ECDSACurve, SP1AffinePointTrait};

use elliptic_curve::{
    group::{cofactor::CofactorGroup, prime::PrimeGroup},
    sec1::CompressedPoint,
};

use elliptic_curve::{
    ff::{Field, PrimeField},
    group::{Curve, Group, GroupEncoding},
    point::{AffineCoordinates, DecompactPoint, DecompressPoint},
    rand_core::RngCore,
    sec1::{self, FromEncodedPoint, ToEncodedPoint},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::DefaultIsZeroes,
    CurveArithmetic,
};

use std::iter::{Product, Sum};
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Scalar<ScalarImpl: PrimeField>(ScalarImpl);

impl<ScalarImpl: PrimeField> Field for Scalar<ScalarImpl> {
    const ONE: Self = Scalar(ScalarImpl::ONE);
    const ZERO: Self = Scalar(ScalarImpl::ZERO);

    fn random(rng: impl RngCore) -> Self {
        Scalar(ScalarImpl::random(rng))
    }

    fn double(&self) -> Self {
        Scalar(self.0.double())
    }

    fn invert(&self) -> CtOption<Self> {
        self.0.invert().map(Scalar)
    }

    fn is_zero(&self) -> Choice {
        self.0.is_zero()
    }

    fn square(&self) -> Self {
        Scalar(self.0.square())
    }

    fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        let (c, result) = ScalarImpl::sqrt_ratio(&num.0, &div.0);

        (c, Scalar(result))
    }
}

impl<ScalarImpl: PrimeField> PrimeField for Scalar<ScalarImpl> {
    type Repr = ScalarImpl::Repr;

    /// Modulus of the field written as a string for debugging purposes.
    ///
    /// The encoding of the modulus is implementation-specific. Generic users of the
    /// `PrimeField` trait should treat this string as opaque.
    const MODULUS: &'static str = ScalarImpl::MODULUS;

    /// How many bits are needed to represent an element of this field.
    const NUM_BITS: u32 = ScalarImpl::NUM_BITS;

    /// How many bits of information can be reliably stored in the field element.
    ///
    /// This is usually `Self::NUM_BITS - 1`.
    const CAPACITY: u32 = ScalarImpl::CAPACITY;

    /// Inverse of $2$ in the field.
    const TWO_INV: Self = Scalar(ScalarImpl::TWO_INV);

    /// A fixed multiplicative generator of `modulus - 1` order. This element must also be
    /// a quadratic nonresidue.
    ///
    /// It can be calculated using [SageMath] as `GF(modulus).primitive_element()`.
    ///
    /// Implementations of this trait MUST ensure that this is the generator used to
    /// derive `Self::ROOT_OF_UNITY`.
    ///
    /// [SageMath]: httpScalarImpl://www.sagemath.org/
    const MULTIPLICATIVE_GENERATOR: Self = Scalar(ScalarImpl::MULTIPLICATIVE_GENERATOR);

    /// An integer `s` satisfying the equation `2^s * t = modulus - 1` with `t` odd.
    ///
    /// This is the number of leading zero bits in the little-endian bit representation of
    /// `modulus - 1`.
    const S: u32 = ScalarImpl::S;

    /// The `2^s` root of unity.
    ///
    /// It can be calculated by exponentiating `Self::MULTIPLICATIVE_GENERATOR` by `t`,
    /// where `t = (modulus - 1) >> Self::S`.
    const ROOT_OF_UNITY: Self = Scalar(ScalarImpl::ROOT_OF_UNITY);

    /// Inverse of [`Self::ROOT_OF_UNITY`].
    const ROOT_OF_UNITY_INV: Self = Scalar(ScalarImpl::ROOT_OF_UNITY_INV);

    /// Generator of the `t-order` multiplicative subgroup.
    ///
    /// It can be calculated by exponentiating [`Self::MULTIPLICATIVE_GENERATOR`] by `2^s`,
    /// where `s` is [`Self::S`].
    const DELTA: Self = Scalar(ScalarImpl::DELTA);

    fn from_repr(repr: Self::Repr) -> CtOption<Self> {
        ScalarImpl::from_repr(repr).map(Scalar)
    }

    fn to_repr(&self) -> Self::Repr {
        self.0.to_repr()
    }

    fn is_odd(&self) -> Choice {
        self.0.is_odd()
    }
}

impl<ScalarImpl: PrimeField> From<u64> for Scalar<ScalarImpl> {
    fn from(v: u64) -> Self {
        Scalar(ScalarImpl::from(v))
    }
}

impl<ScalarImpl: PrimeField> Add<Scalar<ScalarImpl>> for Scalar<ScalarImpl> {
    type Output = Scalar<ScalarImpl>;

    fn add(self, rhs: Scalar<ScalarImpl>) -> Self::Output {
        Scalar(self.0.add(&rhs.0))
    }
}

impl<ScalarImpl: PrimeField> Add<&Scalar<ScalarImpl>> for Scalar<ScalarImpl> {
    type Output = Scalar<ScalarImpl>;

    fn add(self, rhs: &Scalar<ScalarImpl>) -> Self::Output {
        Scalar(self.0.add(&rhs.0))
    }
}

impl<ScalarImpl: PrimeField> AddAssign<Scalar<ScalarImpl>> for Scalar<ScalarImpl> {
    fn add_assign(&mut self, rhs: Scalar<ScalarImpl>) {
        self.0.add_assign(&rhs.0);
    }
}

impl<ScalarImpl: PrimeField> AddAssign<&Scalar<ScalarImpl>> for Scalar<ScalarImpl> {
    fn add_assign(&mut self, rhs: &Scalar<ScalarImpl>) {
        self.0.add_assign(&rhs.0);
    }
}

impl<ScalarImpl: PrimeField> Sub<Scalar<ScalarImpl>> for Scalar<ScalarImpl> {
    type Output = Scalar<ScalarImpl>;

    fn sub(self, rhs: Scalar<ScalarImpl>) -> Self::Output {
        Scalar(self.0.sub(&rhs.0))
    }
}

impl<ScalarImpl: PrimeField> Sub<&Scalar<ScalarImpl>> for Scalar<ScalarImpl> {
    type Output = Scalar<ScalarImpl>;

    fn sub(self, rhs: &Scalar<ScalarImpl>) -> Self::Output {
        Scalar(self.0.sub(&rhs.0))
    }
}

impl<ScalarImpl: PrimeField> SubAssign<Scalar<ScalarImpl>> for Scalar<ScalarImpl> {
    fn sub_assign(&mut self, rhs: Scalar<ScalarImpl>) {
        self.0.sub_assign(&rhs.0);
    }
}

impl<ScalarImpl: PrimeField> SubAssign<&Scalar<ScalarImpl>> for Scalar<ScalarImpl> {
    fn sub_assign(&mut self, rhs: &Scalar<ScalarImpl>) {
        self.0.sub_assign(&rhs.0);
    }
}

impl<ScalarImpl: PrimeField> Mul<Scalar<ScalarImpl>> for Scalar<ScalarImpl> {
    type Output = Scalar<ScalarImpl>;

    fn mul(self, rhs: Scalar<ScalarImpl>) -> Self::Output {
        Scalar(self.0.mul(&rhs.0))
    }
}

impl<ScalarImpl: PrimeField> Mul<&Scalar<ScalarImpl>> for Scalar<ScalarImpl> {
    type Output = Scalar<ScalarImpl>;

    fn mul(self, rhs: &Scalar<ScalarImpl>) -> Self::Output {
        Scalar(self.0.mul(&rhs.0))
    }
}

impl<ScalarImpl: PrimeField> MulAssign<Scalar<ScalarImpl>> for Scalar<ScalarImpl> {
    fn mul_assign(&mut self, rhs: Scalar<ScalarImpl>) {
        self.0.mul_assign(&rhs.0);
    }
}

impl<ScalarImpl: PrimeField> MulAssign<&Scalar<ScalarImpl>> for Scalar<ScalarImpl> {
    fn mul_assign(&mut self, rhs: &Scalar<ScalarImpl>) {
        self.0.mul_assign(&rhs.0);
    }
}

impl<ScalarImpl: PrimeField> Neg for Scalar<ScalarImpl> {
    type Output = Scalar<ScalarImpl>;

    fn neg(self) -> Self::Output {
        Scalar(self.0.neg())
    }
}

impl<ScalarImpl: PrimeField> Product<Scalar<ScalarImpl>> for Scalar<ScalarImpl> {
    fn product<I: IntoIterator<Item = Scalar<ScalarImpl>>>(iter: I) -> Self {
        Scalar(ScalarImpl::product(iter.into_iter().map(|s| s.0)))
    }
}

impl<'a, ScalarImpl: PrimeField> Product<&'a Scalar<ScalarImpl>> for Scalar<ScalarImpl> {
    fn product<I: IntoIterator<Item = &'a Scalar<ScalarImpl>>>(iter: I) -> Self {
        Scalar(ScalarImpl::product(iter.into_iter().map(|s| s.0)))
    }
}

impl<ScalarImpl: PrimeField> Sum<Scalar<ScalarImpl>> for Scalar<ScalarImpl> {
    fn sum<I: IntoIterator<Item = Scalar<ScalarImpl>>>(iter: I) -> Self {
        Scalar(ScalarImpl::sum(iter.into_iter().map(|s| s.0)))
    }
}

impl<'a, ScalarImpl: PrimeField> Sum<&'a Scalar<ScalarImpl>> for Scalar<ScalarImpl> {
    fn sum<I: IntoIterator<Item = &'a Scalar<ScalarImpl>>>(iter: I) -> Self {
        Scalar(ScalarImpl::sum(iter.into_iter().map(|s| s.0)))
    }
}

impl<ScalarImpl: PrimeField> ConstantTimeEq for Scalar<ScalarImpl> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<ScalarImpl: PrimeField> ConditionallySelectable for Scalar<ScalarImpl> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Scalar(ScalarImpl::conditional_select(&a.0, &b.0, choice))
    }
}
