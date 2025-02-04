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

// Specialization please save us !!!
//
// Note: this is a big smell to satisfy the `C::Scalar: Into<C::Uint>` bound.
//
// We cant make this a generic conversion because the compiler
// claims its possible for `C::Uint = Scalar<C>`
// and this causes overlapping impl of `From<T> for T`.
//
// Another way to get around this is to create a new type `Uint<Self>`
// for which we require `CurveArithmetic<Uint = Uint<Self>>`, and add
// a new GAT on `ECDSACurve` for `UintImpl`.
// This means we have `struct Uint<C>(C::UintImpl)`.
//
// However, this is fine for now because all of our curves are 32 bytes.
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
    /// Note: Implentors should ensure these methods normalize first.
    fn to_bytes(&self) -> FieldBytes<C>;
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
