use super::{AffinePoint, ECDSACurve, SP1AffinePointTrait, Scalar};

use elliptic_curve::{
    group::{cofactor::CofactorGroup, prime::PrimeGroup},
    ops::MulByGenerator,
    sec1::CompressedPoint,
};

use elliptic_curve::{
    ff::{Field, PrimeField},
    group::{Curve, Group, GroupEncoding},
    ops::LinearCombination,
    point::{AffineCoordinates, DecompactPoint, DecompressPoint},
    rand_core::RngCore,
    sec1::{self, FromEncodedPoint, ToEncodedPoint},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::DefaultIsZeroes,
    CurveArithmetic,
};

use std::iter::Sum;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

#[derive(Clone, Copy, Debug)]
pub struct ProjectivePoint<C: ECDSACurve> {
    /// The inner affine point.
    ///
    /// SP1 uses affine arithmetic for all operations.
    pub inner: AffinePoint<C>,
}

impl<C: ECDSACurve> ProjectivePoint<C> {
    pub fn identity() -> Self {
        ProjectivePoint { inner: AffinePoint::<C>::identity() }
    }

    pub fn to_affine(self) -> AffinePoint<C> {
        self.inner
    }

    fn to_zkvm_point(self) -> C::SP1AffinePoint {
        self.inner.inner
    }

    fn as_zkvm_point(&self) -> &C::SP1AffinePoint {
        &self.inner.inner
    }

    fn as_mut_zkvm_point(&mut self) -> &mut C::SP1AffinePoint {
        &mut self.inner.inner
    }

    pub fn is_identity(&self) -> Choice {
        self.inner.is_identity()
    }

    fn from_zkvm_point(p: C::SP1AffinePoint) -> Self {
        Self { inner: AffinePoint { inner: p } }
    }
}

impl<C: ECDSACurve> From<AffinePoint<C>> for ProjectivePoint<C> {
    fn from(p: AffinePoint<C>) -> Self {
        ProjectivePoint { inner: p }
    }
}

impl<C: ECDSACurve> From<&AffinePoint<C>> for ProjectivePoint<C> {
    fn from(p: &AffinePoint<C>) -> Self {
        ProjectivePoint { inner: *p }
    }
}

impl<C: ECDSACurve> From<ProjectivePoint<C>> for AffinePoint<C> {
    fn from(p: ProjectivePoint<C>) -> Self {
        p.inner
    }
}

impl<C: ECDSACurve> From<&ProjectivePoint<C>> for AffinePoint<C> {
    fn from(p: &ProjectivePoint<C>) -> Self {
        p.inner
    }
}

impl<C: ECDSACurve> Group for ProjectivePoint<C> {
    // Ideally we could just have this type be
    // type Scalar = <C as CurveArithmetic>::Scalar,
    // however trait resolution fails on the `Mul` implementation.
    // specifcally for<'a> Mul<&'a C::Scalar> is broken.
    //
    // These are known limitiations of GATs though, so we must wait for the new trait resolver
    // so we can clean this up.
    type Scalar = Scalar<C::ScalarImpl>;

    fn identity() -> Self {
        Self::identity()
    }

    fn random(rng: impl RngCore) -> Self {
        ProjectivePoint::<C>::generator() * Self::Scalar::random(rng)
    }

    fn double(&self) -> Self {
        *self + self
    }

    fn generator() -> Self {
        Self { inner: AffinePoint::<C>::generator() }
    }

    fn is_identity(&self) -> Choice {
        self.inner.is_identity()
    }
}

impl<C: ECDSACurve> Curve for ProjectivePoint<C> {
    type AffineRepr = AffinePoint<C>;

    fn to_affine(&self) -> Self::AffineRepr {
        self.inner
    }
}

impl<C: ECDSACurve> MulByGenerator for ProjectivePoint<C> {}

impl<C: ECDSACurve> LinearCombination for ProjectivePoint<C> {
    fn lincomb(x: &Self, k: &Self::Scalar, y: &Self, l: &Self::Scalar) -> Self {
        let x = x.to_zkvm_point();
        let y = y.to_zkvm_point();

        let a_bits_le = be_bytes_to_le_bits(k.to_repr().as_ref());
        let b_bits_le = be_bytes_to_le_bits(l.to_repr().as_ref());

        let sp1_point =
            C::SP1AffinePoint::multi_scalar_multiplication(&a_bits_le, x, &b_bits_le, y);

        Self::from_zkvm_point(sp1_point)
    }
}

// Scalar Mul

impl<C: ECDSACurve> Mul<Scalar<C::ScalarImpl>> for ProjectivePoint<C> {
    type Output = ProjectivePoint<C>;

    fn mul(mut self, rhs: Scalar<C::ScalarImpl>) -> Self::Output {
        let sp1_point = self.as_mut_zkvm_point();
        let mut rhs = rhs.to_repr();

        sp1_point.mul_assign(&be_bytes_to_le_words(rhs.as_mut()));

        self
    }
}

impl<C: ECDSACurve> Mul<&Scalar<C::ScalarImpl>> for ProjectivePoint<C> {
    type Output = ProjectivePoint<C>;

    fn mul(mut self, rhs: &Scalar<C::ScalarImpl>) -> Self::Output {
        let sp1_point = self.as_mut_zkvm_point();
        let mut rhs = rhs.to_repr();

        sp1_point.mul_assign(&be_bytes_to_le_words(rhs.as_mut()));

        self
    }
}

impl<C: ECDSACurve> MulAssign<Scalar<C::ScalarImpl>> for ProjectivePoint<C> {
    fn mul_assign(&mut self, rhs: Scalar<C::ScalarImpl>) {
        let mut rhs = rhs.to_repr();

        self.as_mut_zkvm_point().mul_assign(&be_bytes_to_le_words(rhs.as_mut()));
    }
}

impl<C: ECDSACurve> MulAssign<&Scalar<C::ScalarImpl>> for ProjectivePoint<C> {
    fn mul_assign(&mut self, rhs: &Scalar<C::ScalarImpl>) {
        let mut rhs = rhs.to_repr();

        self.as_mut_zkvm_point().mul_assign(&be_bytes_to_le_words(rhs.as_mut()));
    }
}

// Projective arithmetic

impl<C: ECDSACurve> Neg for ProjectivePoint<C> {
    type Output = ProjectivePoint<C>;

    fn neg(self) -> Self::Output {
        if self.is_identity().into() {
            return self;
        }

        let point = self.to_affine();
        let (x, y) = point.field_elements();

        AffinePoint::<C>::from_field_elements_unchecked(x, y.neg()).into()
    }
}

impl<C: ECDSACurve> Add<ProjectivePoint<C>> for ProjectivePoint<C> {
    type Output = ProjectivePoint<C>;

    fn add(mut self, rhs: ProjectivePoint<C>) -> Self::Output {
        self.as_mut_zkvm_point().add_assign(rhs.as_zkvm_point());

        self
    }
}

impl<C: ECDSACurve> Add<&ProjectivePoint<C>> for ProjectivePoint<C> {
    type Output = ProjectivePoint<C>;

    fn add(mut self, rhs: &ProjectivePoint<C>) -> Self::Output {
        self.as_mut_zkvm_point().add_assign(rhs.as_zkvm_point());

        self
    }
}

impl<C: ECDSACurve> Sub<ProjectivePoint<C>> for ProjectivePoint<C> {
    type Output = ProjectivePoint<C>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: ProjectivePoint<C>) -> Self::Output {
        self + rhs.neg()
    }
}

impl<C: ECDSACurve> Sub<&ProjectivePoint<C>> for ProjectivePoint<C> {
    type Output = ProjectivePoint<C>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: &ProjectivePoint<C>) -> Self::Output {
        self + (*rhs).neg()
    }
}

impl<C: ECDSACurve> Sum<ProjectivePoint<C>> for ProjectivePoint<C> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::identity(), |a, b| a + b)
    }
}

impl<'a, C: ECDSACurve> Sum<&'a ProjectivePoint<C>> for ProjectivePoint<C> {
    fn sum<I: Iterator<Item = &'a ProjectivePoint<C>>>(iter: I) -> Self {
        iter.cloned().sum()
    }
}

impl<C: ECDSACurve> AddAssign<ProjectivePoint<C>> for ProjectivePoint<C> {
    fn add_assign(&mut self, rhs: ProjectivePoint<C>) {
        self.as_mut_zkvm_point().add_assign(rhs.as_zkvm_point());
    }
}

impl<C: ECDSACurve> AddAssign<&ProjectivePoint<C>> for ProjectivePoint<C> {
    fn add_assign(&mut self, rhs: &ProjectivePoint<C>) {
        self.as_mut_zkvm_point().add_assign(rhs.as_zkvm_point());
    }
}

impl<C: ECDSACurve> SubAssign<ProjectivePoint<C>> for ProjectivePoint<C> {
    fn sub_assign(&mut self, rhs: ProjectivePoint<C>) {
        self.as_mut_zkvm_point().add_assign(rhs.neg().as_zkvm_point());
    }
}

impl<C: ECDSACurve> SubAssign<&ProjectivePoint<C>> for ProjectivePoint<C> {
    fn sub_assign(&mut self, rhs: &ProjectivePoint<C>) {
        self.as_mut_zkvm_point().add_assign(rhs.neg().as_zkvm_point());
    }
}

impl<C: ECDSACurve> Default for ProjectivePoint<C> {
    fn default() -> Self {
        Self::identity()
    }
}

// Mixed arithmetic

impl<C: ECDSACurve> Add<AffinePoint<C>> for ProjectivePoint<C> {
    type Output = ProjectivePoint<C>;

    fn add(self, rhs: AffinePoint<C>) -> Self::Output {
        self + ProjectivePoint { inner: rhs }
    }
}

impl<C: ECDSACurve> Add<&AffinePoint<C>> for ProjectivePoint<C> {
    type Output = ProjectivePoint<C>;

    fn add(self, rhs: &AffinePoint<C>) -> Self::Output {
        self + ProjectivePoint { inner: *rhs }
    }
}

impl<C: ECDSACurve> AddAssign<AffinePoint<C>> for ProjectivePoint<C> {
    fn add_assign(&mut self, rhs: AffinePoint<C>) {
        self.as_mut_zkvm_point().add_assign(&rhs.inner);
    }
}

impl<C: ECDSACurve> AddAssign<&AffinePoint<C>> for ProjectivePoint<C> {
    fn add_assign(&mut self, rhs: &AffinePoint<C>) {
        self.as_mut_zkvm_point().add_assign(&rhs.inner);
    }
}

impl<C: ECDSACurve> Sub<AffinePoint<C>> for ProjectivePoint<C> {
    type Output = ProjectivePoint<C>;

    fn sub(self, rhs: AffinePoint<C>) -> Self::Output {
        self - ProjectivePoint { inner: rhs }
    }
}

impl<C: ECDSACurve> Sub<&AffinePoint<C>> for ProjectivePoint<C> {
    type Output = ProjectivePoint<C>;

    fn sub(self, rhs: &AffinePoint<C>) -> Self::Output {
        self - ProjectivePoint { inner: *rhs }
    }
}

impl<C: ECDSACurve> SubAssign<AffinePoint<C>> for ProjectivePoint<C> {
    fn sub_assign(&mut self, rhs: AffinePoint<C>) {
        let projective = ProjectivePoint { inner: rhs }.neg();

        self.as_mut_zkvm_point().add_assign(projective.as_zkvm_point());
    }
}

impl<C: ECDSACurve> SubAssign<&AffinePoint<C>> for ProjectivePoint<C> {
    fn sub_assign(&mut self, rhs: &AffinePoint<C>) {
        let projective = ProjectivePoint { inner: *rhs }.neg();

        self.as_mut_zkvm_point().add_assign(projective.as_zkvm_point());
    }
}

// todo: not actually true?
impl<C: ECDSACurve> DefaultIsZeroes for ProjectivePoint<C> {}

impl<C: ECDSACurve> ConditionallySelectable for ProjectivePoint<C> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        // Note: we dont care about constant time operattions in the vm.
        if choice.into() {
            *b
        } else {
            *a
        }
    }
}

impl<C: ECDSACurve> ConstantTimeEq for ProjectivePoint<C> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.inner.ct_eq(&other.inner)
    }
}

impl<C: ECDSACurve> PartialEq for ProjectivePoint<C> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<C: ECDSACurve> Eq for ProjectivePoint<C> {}

// Traits for hash2curve
impl<C: ECDSACurve> GroupEncoding for ProjectivePoint<C> {
    type Repr = CompressedPoint<C>;

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        <AffinePoint<C> as GroupEncoding>::from_bytes(bytes).map(Into::into)
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        // No unchecked conversion possible for compressed points
        Self::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Self::Repr {
        self.inner.to_bytes()
    }
}

impl<C: ECDSACurve> PrimeGroup for ProjectivePoint<C> {}

/// The scalar field has prime order, so the cofactor is 1.
impl<C: ECDSACurve> CofactorGroup for ProjectivePoint<C> {
    type Subgroup = Self;

    fn clear_cofactor(&self) -> Self {
        *self
    }

    fn into_subgroup(self) -> CtOption<Self> {
        CtOption::new(self, Choice::from(1))
    }

    fn is_torsion_free(&self) -> Choice {
        Choice::from(1)
    }
}

#[inline]
fn be_bytes_to_le_words(bytes: &mut [u8]) -> [u32; 16] {
    bytes.reverse();

    core::array::from_fn(|_| {
        bytes.chunks(4).map(|b| u32::from_le_bytes(b.try_into().unwrap())).next().unwrap()
    })
}

/// Convert big-endian bytes with the most significant bit first to little-endian bytes with the least significant bit first.
/// Panics: If the bytes have len > 32.
#[inline]
fn be_bytes_to_le_bits(be_bytes: &[u8]) -> [bool; 256] {
    let mut bits = [false; 256];
    // Reverse the byte order to little-endian.
    for (i, &byte) in be_bytes.iter().rev().enumerate() {
        for j in 0..8 {
            // Flip the bit order so the least significant bit is now the first bit of the chunk.
            bits[i * 8 + j] = ((byte >> j) & 1) == 1;
        }
    }
    bits
}
