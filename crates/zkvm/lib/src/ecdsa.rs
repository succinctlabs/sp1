use crate::utils::AffinePoint as SP1AffinePointTrait;

use elliptic_curve::{
    ff, generic_array::typenum::consts::U32, subtle::CtOption, CurveArithmetic, FieldBytes,
    PrimeField,
};
use std::ops::Neg;

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
    Self: CurveArithmetic<FieldBytesSize = FIELD_BYTES_SIZE, Scalar = Scalar<Self::ScalarImpl>>,
{
    type FieldElement: Field<Self> + Neg<Output = Self::FieldElement>;

    type ScalarImpl: PrimeField;

    /// The number of limbs in the field element.
    ///
    /// Note: At the moment, the only supported ECDSA curvers are secp256k1 and secp256r1.
    /// These both have 16 limbs in their field elements.
    type SP1AffinePoint: ECDSAPoint;

    /// The `a` coefficient in the curve equation.
    const EQUATION_A: Self::FieldElement;

    /// The `b` coefficient in the curve equation.
    const EQUATION_B: Self::FieldElement;
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
