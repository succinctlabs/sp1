use crate::utils::AffinePoint as SP1AffinePointTrait;

use elliptic_curve::{
    bigint::U256,
    ff,
    generic_array::typenum::consts::U32,
    ops::{Invert, Reduce},
    scalar::{FromUintUnchecked, IsHigh},
    subtle::CtOption,
    zeroize::DefaultIsZeroes,
    CurveArithmetic, FieldBytes, ScalarPrimitive,
};
use std::ops::{Neg, ShrAssign};

pub mod affine;
pub use affine::AffinePoint;

pub mod projective;
pub use projective::ProjectivePoint;

pub mod scalar;
pub use scalar::Scalar;

/// NOTE: Currently, the only supported ECDSA curves are secp256k1 and secp256r1.
/// These both have 16 limbs in their field elements.
const FIELD_LIMBS: usize = 16;

/// The number of bytes in a field element as an [`usize`].
const FIELD_BYTES_SIZE_USIZE: usize = 32;

/// The number of bytes in a field element as an [`elliptic_curve::generic_array::U32`].
#[allow(non_camel_case_types)]
type FIELD_BYTES_SIZE = U32;

/// A weisertstrass curve for ECDSA.
/// Note: This trait is only implemented for 32 byte curves.
pub trait ECDSACurve
where
    Self: CurveArithmetic<FieldBytesSize = FIELD_BYTES_SIZE, Scalar = Scalar<Self>, Uint = U256>,
{
    type FieldElement: Field<Self> + Neg<Output = Self::FieldElement>;

    type ScalarImpl: DefaultIsZeroes
        + From<ScalarPrimitive<Self>>
        + FromUintUnchecked<Uint = Self::Uint>
        + Into<FieldBytes<Self>>
        + Into<ScalarPrimitive<Self>>
        + Into<Self::Uint>
        + Invert<Output = CtOption<Self::ScalarImpl>>
        + IsHigh
        + PartialOrd
        + Reduce<Self::Uint, Bytes = FieldBytes<Self>>
        + ShrAssign<usize>
        + ff::Field
        + ff::PrimeField<Repr = FieldBytes<Self>>;

    /// The underlying [`SP1AffinePointTrait`] implementation.
    type SP1AffinePoint: ECDSAPoint;

    /// The `a` coefficient in the curve equation.
    const EQUATION_A: Self::FieldElement;

    /// The `b` coefficient in the curve equation.
    const EQUATION_B: Self::FieldElement;
}

// Note: The `From<Scalar<C>> for C::Uint` impl is required by the [`CurveArithmetic`] trait.
// Unfortunatly, its impossible to write that at the moment, because Rust lacks specialization, and we
// want to avoid adding this bound everywhere.
//
// For now, have a hardcoded `Uint` type, as we also have `FieldBytesSize`.
//
// Another option is add a new GAT `ECDSACurve::UintImpl` and crate a new type `struct Uint<C>(C::UintImpl)`.
// This would allow us to write the From impl, and also be generic over the `Uint` type.
impl<C: ECDSACurve> From<Scalar<C>> for U256 {
    fn from(scalar: Scalar<C>) -> Self {
        scalar.0.into()
    }
}

/// Alias trait for the [`ff::PrimeField`] with 32 byte field elements.
pub trait Field<C: ECDSACurve>: ff::PrimeField {
    /// Create an instance of self from a FieldBytes.
    fn from_bytes(bytes: &FieldBytes<C>) -> CtOption<Self>;

    /// Convert self to a FieldBytes.
    ///
    /// Note: Implementers should ensure these methods normalize first.
    fn to_bytes(self) -> FieldBytes<C>;

    /// Ensure the field element is normalized.
    fn normalize(self) -> Self;
}

pub type FieldElement<C> = <C as ECDSACurve>::FieldElement;

/// Alias trait for the [`SP1AffinePointTrait`] with 32 byte field elements.
pub trait ECDSAPoint:
    SP1AffinePointTrait<FIELD_LIMBS> + Clone + Copy + std::fmt::Debug + Send + Sync
{
    #[inline]
    fn from(x: &[u8], y: &[u8]) -> Self {
        <Self as SP1AffinePointTrait<FIELD_LIMBS>>::from(x, y)
    }
}

impl<P> ECDSAPoint for P where
    P: SP1AffinePointTrait<FIELD_LIMBS> + Clone + Copy + std::fmt::Debug + Send + Sync
{
}

pub mod ecdh {
    pub use elliptic_curve::ecdh::{diffie_hellman, EphemeralSecret, SharedSecret};

    use super::{AffinePoint, ECDSACurve, Field};

    impl<C: ECDSACurve> From<&AffinePoint<C>> for SharedSecret<C> {
        fn from(affine: &AffinePoint<C>) -> SharedSecret<C> {
            let (x, _) = affine.field_elements();

            x.to_bytes().into()
        }
    }
}
