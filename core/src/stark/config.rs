use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{Pcs, UnivariatePcsWithLde};
use p3_field::{
    extension::{BinomialExtensionField, BinomiallyExtendable},
    PrimeField32, TwoAdicField,
};
use p3_matrix::dense::RowMajorMatrix;

pub type SuperChallenge<Val> = BinomialExtensionField<Val, 4>;

/// A configuration for a STARK.
pub trait StarkGenericConfig {
    /// The field over which trace data is encoded.
    type Val: TwoAdicField + PrimeField32 + BinomiallyExtendable<4>;

    /// The PCS used to commit to trace polynomials.
    type Pcs: UnivariatePcsWithLde<
        Self::Val,
        BinomialExtensionField<Self::Val, 4>,
        RowMajorMatrix<Self::Val>,
        Self::Challenger,
    >;

    /// The challenger (Fiat-Shamir) implementation used.
    type Challenger: FieldChallenger<Self::Val>
        + CanObserve<<Self::Pcs as Pcs<Self::Val, RowMajorMatrix<Self::Val>>>::Commitment>;

    /// Returns the PCS used to commit to trace polynomials.
    fn pcs(&self) -> &Self::Pcs;
}
