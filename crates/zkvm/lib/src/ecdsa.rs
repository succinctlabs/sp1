//! An implementation of the types needed for [`CurveArithmetic`].
//!
//! [`CurveArithmetic`] is a trait that is used in [RustCryptos ECDSA](https://github.com/RustCrypto/signatures).
//!
//! [`CurveArithmetic`] contains all the types needed to implement the ECDSA algorithm over some curve.
//!
//! This implementation is specifcially for use inside the SP1zkVM, and internally it uses our
//! Weierstrass precompiles.
//!
//! In summary, SP1 overrides curve arithmetic entirely, and patches upstream field operations
//! to be more efficient in the VM, such as `sqrt` or `inverse`.

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

/// The affine point type for SP1.
pub mod affine;
pub use affine::AffinePoint;

/// The projective point type for SP1.
pub mod projective;
pub use projective::ProjectivePoint;

/// The scalar type for SP1.
///
/// Note: This is just a wrapper to workaround some GAT limitations.
pub mod scalar;
pub use scalar::Scalar;

/// NOTE: The only supported ECDSA curves are secp256k1 and secp256r1, which both
/// have 8 limbs in their field elements.
const POINT_LIMBS: usize = 8 * 2;

/// The number of bytes in a field element as an [`usize`].
const FIELD_BYTES_SIZE_USIZE: usize = 32;

/// The number of bytes in a field element as an [`elliptic_curve::generic_array::U32`].
#[allow(non_camel_case_types)]
type FIELD_BYTES_SIZE = U32;

/// A [`CurveArithmetic`] implementation for SP1 acceleration.
/// Patched crates will implement this trait to expose their field element type to us.
///
/// Note: This trait only supports 32 byte base field curves.
pub trait ECDSACurve
where
    Self: CurveArithmetic<
        FieldBytesSize = FIELD_BYTES_SIZE,
        Scalar = Scalar<Self>,
        AffinePoint = AffinePoint<Self>,
        ProjectivePoint = ProjectivePoint<Self>,
        Uint = U256,
    >,
{
    type FieldElement: Field<Self> + Neg<Output = Self::FieldElement>;

    /// The underlying [`Scalar`] implementation.
    ///
    /// This "newtype" is needed due to some limitations of GATs.
    ///
    /// Specifically, its impossible to generically implement
    /// `ProjectivePoint<C>: for<'a> Mul<&'a C::Scalar>`,
    /// as required by the [`ff::Group`] trait.
    ///
    /// See this playground for a minimum reproduction:
    /// <https://play.rust-lang.org/?version=stable&mode=debug&edition=2021&gist=507aad241e3609d2f595bd1a95787038>
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

/// Required by the [`CurveArithmetic`] trait.
///
/// Note: In current Rust we cannot write:
/// ```rust
/// impl<C: ECDSACurve> From<Scalar<C>> for C::Uint {
///     fn from(scalar: Scalar<C>) -> Self {
///         scalar.0.into()
///     }
/// }
/// ```
///
/// As the compiler claims that C::Uint may be a Scalar<C>,
/// and this conflicts with the more generic `From<T> for T` implementation.
impl<C: ECDSACurve> From<Scalar<C>> for U256 {
    fn from(scalar: Scalar<C>) -> Self {
        scalar.0.into()
    }
}

/// Alias trait for the [`ff::PrimeField`] with 32 byte field elements.
///
/// Note: All bytes should be considered to be in big-endian format.
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
    SP1AffinePointTrait<POINT_LIMBS> + Clone + Copy + std::fmt::Debug + Send + Sync
{
    #[inline]
    fn from(x: &[u8], y: &[u8]) -> Self {
        <Self as SP1AffinePointTrait<POINT_LIMBS>>::from(x, y)
    }
}

impl<P> ECDSAPoint for P where
    P: SP1AffinePointTrait<POINT_LIMBS> + Clone + Copy + std::fmt::Debug + Send + Sync
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
