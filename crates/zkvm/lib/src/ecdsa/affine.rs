//! Implementation of an affine point, with acceleration for operations in the context of SP1.
//!
//! The [`crate::ecdsa::ProjectivePoint`] type is mainly used in the `ecdsa-core` algorithms,
//! however, in some cases, the affine point is required.
//!
//! Note: When performing curve operations, accelerated crates for SP1 use affine arithmetic instead
//! of projective arithmetic for performance.

use super::{
    ECDSACurve, ECDSAPoint, Field, FieldElement, SP1AffinePointTrait, FIELD_BYTES_SIZE_USIZE,
};

use elliptic_curve::{
    ff::Field as _,
    group::GroupEncoding,
    point::{AffineCoordinates, DecompactPoint, DecompressPoint},
    sec1::{self, CompressedPoint, EncodedPoint, FromEncodedPoint, ToEncodedPoint},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::DefaultIsZeroes,
    FieldBytes, PrimeField,
};
use std::ops::Neg;

#[derive(Clone, Copy, Debug)]
pub struct AffinePoint<C: ECDSACurve> {
    pub inner: C::SP1AffinePoint,
}

impl<C: ECDSACurve> AffinePoint<C> {
    /// Create an affine point from the given field elements, without checking if the point is on
    /// the curve.
    pub fn from_field_elements_unchecked(x: FieldElement<C>, y: FieldElement<C>) -> Self {
        let mut x_slice = x.to_bytes();
        let x_slice = x_slice.as_mut_slice();
        x_slice.reverse();

        let mut y_slice = y.to_bytes();
        let y_slice = y_slice.as_mut_slice();
        y_slice.reverse();

        AffinePoint { inner: <C::SP1AffinePoint as ECDSAPoint>::from(x_slice, y_slice) }
    }

    /// Get the x and y field elements of the point.
    ///
    /// The returned elements are always normalized.
    pub fn field_elements(&self) -> (FieldElement<C>, FieldElement<C>) {
        if self.is_identity().into() {
            return (FieldElement::<C>::ZERO, FieldElement::<C>::ZERO);
        }

        let bytes = self.inner.to_le_bytes();

        let mut x_bytes: [u8; FIELD_BYTES_SIZE_USIZE] =
            bytes[..FIELD_BYTES_SIZE_USIZE].try_into().unwrap();

        x_bytes.reverse();

        let mut y_bytes: [u8; FIELD_BYTES_SIZE_USIZE] =
            bytes[FIELD_BYTES_SIZE_USIZE..].try_into().unwrap();

        y_bytes.reverse();

        let x = FieldElement::<C>::from_bytes(&x_bytes.into()).unwrap();
        let y = FieldElement::<C>::from_bytes(&y_bytes.into()).unwrap();
        (x, y)
    }

    /// Get the generator point.
    pub fn generator() -> Self {
        AffinePoint { inner: C::SP1AffinePoint::GENERATOR_T }
    }

    /// Get the identity point.
    pub fn identity() -> Self {
        AffinePoint { inner: C::SP1AffinePoint::identity() }
    }

    /// Check if the point is the identity point.
    pub fn is_identity(&self) -> Choice {
        Choice::from(self.inner.is_identity() as u8)
    }
}

impl<C: ECDSACurve> FromEncodedPoint<C> for AffinePoint<C> {
    fn from_encoded_point(point: &EncodedPoint<C>) -> CtOption<Self> {
        match point.coordinates() {
            sec1::Coordinates::Identity => CtOption::new(Self::identity(), 1.into()),
            sec1::Coordinates::Compact { x } => Self::decompact(x),
            sec1::Coordinates::Compressed { x, y_is_odd } => {
                AffinePoint::<C>::decompress(x, Choice::from(y_is_odd as u8))
            }
            sec1::Coordinates::Uncompressed { x, y } => {
                let x = FieldElement::<C>::from_bytes(x);
                let y = FieldElement::<C>::from_bytes(y);

                x.and_then(|x| {
                    y.and_then(|y| {
                        // Ensure the point is on the curve.
                        let lhs = (y * y).normalize();
                        let rhs = (x * x * x) + (C::EQUATION_A * x) + C::EQUATION_B;

                        let point = Self::from_field_elements_unchecked(x, y);

                        CtOption::new(point, lhs.ct_eq(&rhs.normalize()))
                    })
                })
            }
        }
    }
}

impl<C: ECDSACurve> ToEncodedPoint<C> for AffinePoint<C> {
    fn to_encoded_point(&self, compress: bool) -> EncodedPoint<C> {
        // If the point is the identity point, just return the identity point.
        if self.is_identity().into() {
            return EncodedPoint::<C>::identity();
        }

        let (x, y) = self.field_elements();

        // The field elements are already normalized by virtue of being created via `FromBytes`.
        EncodedPoint::<C>::from_affine_coordinates(&x.to_bytes(), &y.to_bytes(), compress)
    }
}

impl<C: ECDSACurve> DecompressPoint<C> for AffinePoint<C> {
    fn decompress(x_bytes: &FieldBytes<C>, y_is_odd: Choice) -> CtOption<Self> {
        FieldElement::<C>::from_bytes(x_bytes).and_then(|x| {
            let alpha = (x * x * x) + (C::EQUATION_A * x) + C::EQUATION_B;
            let beta = alpha.sqrt();

            beta.map(|beta| {
                // Ensure the element is normalized for consistency.
                let beta = beta.normalize();

                let y = FieldElement::<C>::conditional_select(
                    &beta.neg(),
                    &beta,
                    beta.is_odd().ct_eq(&y_is_odd),
                );

                // X is normalized by virtue of being created via `FromBytes`.
                AffinePoint::from_field_elements_unchecked(x, y.normalize())
            })
        })
    }
}

impl<C: ECDSACurve> DecompactPoint<C> for AffinePoint<C> {
    fn decompact(x_bytes: &FieldBytes<C>) -> CtOption<Self> {
        Self::decompress(x_bytes, Choice::from(0))
    }
}

impl<C: ECDSACurve> AffineCoordinates for AffinePoint<C> {
    type FieldRepr = FieldBytes<C>;

    fn x(&self) -> FieldBytes<C> {
        let (x, _) = self.field_elements();

        x.to_bytes()
    }

    fn y_is_odd(&self) -> Choice {
        let (_, y) = self.field_elements();

        // As field elements are created via [`Field::from_bytes`], they are already normalized.
        y.is_odd()
    }
}

impl<C: ECDSACurve> ConditionallySelectable for AffinePoint<C> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        // Conditional select is a constant time if-else operation.
        //
        // In the SP1 vm, there are no attempts made to prevent side channel attacks.
        if choice.into() {
            *b
        } else {
            *a
        }
    }
}

impl<C: ECDSACurve> ConstantTimeEq for AffinePoint<C> {
    fn ct_eq(&self, other: &Self) -> Choice {
        let (x1, y1) = self.field_elements();
        let (x1, y1) = (x1, y1);

        let (x2, y2) = other.field_elements();
        let (x2, y2) = (x2, y2);

        // These are already normalized by virtue of being created via `FromBytes`.
        x1.ct_eq(&x2) & y1.ct_eq(&y2)
    }
}

impl<C: ECDSACurve> PartialEq for AffinePoint<C> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<C: ECDSACurve> Eq for AffinePoint<C> {}

impl<C: ECDSACurve> Default for AffinePoint<C> {
    fn default() -> Self {
        AffinePoint::identity()
    }
}

impl<C: ECDSACurve> DefaultIsZeroes for AffinePoint<C> {}

impl<C: ECDSACurve> GroupEncoding for AffinePoint<C> {
    type Repr = CompressedPoint<C>;

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        EncodedPoint::<C>::from_bytes(bytes)
            .map(|point| CtOption::new(point, Choice::from(1)))
            .unwrap_or_else(|_| {
                // SEC1 identity encoding is technically 1-byte 0x00, but the
                // `GroupEncoding` API requires a fixed-width `Repr`.
                let is_identity = bytes.ct_eq(&Self::Repr::default());
                CtOption::new(EncodedPoint::<C>::identity(), is_identity)
            })
            .and_then(|point| Self::from_encoded_point(&point))
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        // There is no unchecked conversion for compressed points.
        Self::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Self::Repr {
        let encoded = self.to_encoded_point(true);
        let mut result = CompressedPoint::<C>::default();
        result[..encoded.len()].copy_from_slice(encoded.as_bytes());
        result
    }
}
