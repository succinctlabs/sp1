use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{Pcs, UnivariatePcsWithLde};
use p3_field::{ExtensionField, PrimeField32, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use serde::Serialize;

/// A configuration for a STARK.
pub trait StarkGenericConfig: Clone {
    /// The field over which trace data is encoded.
    type Val: TwoAdicField + PrimeField32;

    /// The field from which random challenges are drawn.
    type Challenge: ExtensionField<Self::Val> + TwoAdicField + Serialize;

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
