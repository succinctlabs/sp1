use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{Pcs, UnivariatePcsWithLde};
use p3_field::{AbstractExtensionField, ExtensionField, PackedField, Res, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;

/// A configuration for a STARK.
pub trait StarkConfig {
    /// The field over which trace data is encoded.
    type Val: TwoAdicField;

    /// The packed version of `Val` to accelerate vector-friendly computations.
    type PackedVal: PackedField<Scalar = Self::Val>;

    /// The field from which random challenges are drawn.
    type Challenge: ExtensionField<Self::Val> + TwoAdicField;

    /// The packed version of `Challenge` to accelerate vector-friendly computations.
    type PackedChallenge: AbstractExtensionField<Self::PackedVal, F = Self::Challenge> + Copy;

    /// The challenge algebra `Challenge[X]/f(X)`, where `Challenge = Val[X]/f(X)`.
    type ChallengeAlgebra: AbstractExtensionField<Res<Self::Val, Self::Challenge>, F = Self::Challenge>
        + Copy;

    /// The PCS used to commit to trace polynomials.
    type Pcs: UnivariatePcsWithLde<
        Self::Val,
        Self::Challenge,
        RowMajorMatrix<Self::Val>,
        Self::Challenger,
    >;

    /// The challenger (Fiat-Shamir) implementation used.
    type Challenger: FieldChallenger<Self::Val>
        + CanObserve<<Self::Pcs as Pcs<Self::Val, RowMajorMatrix<Self::Val>>>::Commitment>;

    /// Returns the PCS used to commit to trace polynomials.
    fn pcs(&self) -> &Self::Pcs;
}
