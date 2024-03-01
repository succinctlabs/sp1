use p3_commit::{Pcs, UnivariatePcs, UnivariatePcsWithLde};
use p3_fri::{TwoAdicFriPcs, TwoAdicFriPcsGenericConfig};
use p3_matrix::dense::RowMajorMatrix;
use sp1_core::stark::StarkGenericConfig;

struct RecursiveTwoAdicFriPCS<
    C: StarkGenericConfig<Pcs = TwoAdicFriPcs<T>>,
    T: TwoAdicFriPcsGenericConfig,
> {
    pcs: C::Pcs,
}

impl<
        C: StarkGenericConfig<Pcs = TwoAdicFriPcs<T>, Val = T::Val>,
        T: TwoAdicFriPcsGenericConfig,
    > RecursiveTwoAdicFriPCS<C, T>
{
    fn new(pcs: C::Pcs) -> Self {
        Self { pcs }
    }
}

impl<C: StarkGenericConfig<Pcs = TwoAdicFriPcs<T>>, T: TwoAdicFriPcsGenericConfig>
    UnivariatePcsWithLde<T::Val, T::Challenge, RowMajorMatrix<T::Val>, T::Challenger>
    for RecursiveTwoAdicFriPCS<C, T>
{
    type Lde<'a> = <C::Pcs as UnivariatePcsWithLde<
        T::Val,
        T::Challenge,
        RowMajorMatrix<T::Val>,
        T::Challenger,
    >>::Lde<'a> where T: 'a, C: 'a;

    fn coset_shift(&self) -> T::Val {
        <TwoAdicFriPcs<T> as UnivariatePcsWithLde<
            T::Val,
            T::Challenge,
            RowMajorMatrix<T::Val>,
            T::Challenger,
        >>::coset_shift(&self.pcs)
    }

    fn log_blowup(&self) -> usize {
        <TwoAdicFriPcs<T> as UnivariatePcsWithLde<
            T::Val,
            T::Challenge,
            RowMajorMatrix<T::Val>,
            T::Challenger,
        >>::log_blowup(&self.pcs)
    }

    fn get_ldes<'a, 'b>(&'a self, prover_data: &'b Self::ProverData) -> Vec<Self::Lde<'b>>
    where
        'a: 'b,
    {
        <TwoAdicFriPcs<T> as UnivariatePcsWithLde<
            T::Val,
            T::Challenge,
            RowMajorMatrix<T::Val>,
            T::Challenger,
        >>::get_ldes(&self.pcs, prover_data)
    }

    fn commit_shifted_batches(
        &self,
        polynomials: Vec<RowMajorMatrix<T::Val>>,
        coset_shift: &[T::Val],
    ) -> (Self::Commitment, Self::ProverData) {
        self.pcs.commit_shifted_batches(polynomials, coset_shift)
    }

    fn commit_shifted_batch(
        &self,
        polynomials: RowMajorMatrix<T::Val>,
        coset_shift: T::Val,
    ) -> (Self::Commitment, Self::ProverData) {
        self.commit_shifted_batches(std::vec![polynomials], &[coset_shift])
    }
}

impl<C: StarkGenericConfig<Pcs = TwoAdicFriPcs<T>>, T: TwoAdicFriPcsGenericConfig>
    UnivariatePcs<T::Val, T::Challenge, RowMajorMatrix<T::Val>, T::Challenger>
    for RecursiveTwoAdicFriPCS<C, T>
{
    fn open_multi_batches(
        &self,
        prover_data_and_points: &[(&Self::ProverData, &[Vec<T::Challenge>])],
        challenger: &mut T::Challenger,
    ) -> (p3_commit::OpenedValues<T::Challenge>, Self::Proof) {
        <TwoAdicFriPcs<T> as UnivariatePcs<
            T::Val,
            T::Challenge,
            RowMajorMatrix<T::Val>,
            T::Challenger,
        >>::open_multi_batches(&self.pcs, prover_data_and_points, challenger)
    }

    fn verify_multi_batches(
        &self,
        commits_and_points: &[(Self::Commitment, &[Vec<T::Challenge>])],
        dims: &[Vec<p3_matrix::Dimensions>],
        values: p3_commit::OpenedValues<T::Challenge>,
        proof: &Self::Proof,
        challenger: &mut T::Challenger,
    ) -> Result<(), Self::Error> {
        <TwoAdicFriPcs<T> as UnivariatePcs<
            T::Val,
            T::Challenge,
            RowMajorMatrix<T::Val>,
            T::Challenger,
        >>::verify_multi_batches(
            &self.pcs,
            commits_and_points,
            dims,
            values,
            proof,
            challenger,
        )
    }
}

impl<C: StarkGenericConfig<Pcs = TwoAdicFriPcs<T>>, T: TwoAdicFriPcsGenericConfig>
    Pcs<T::Val, RowMajorMatrix<T::Val>> for RecursiveTwoAdicFriPCS<C, T>
{
    type Commitment = <C::Pcs as Pcs<T::Val, RowMajorMatrix<T::Val>>>::Commitment;
    type ProverData = <C::Pcs as Pcs<T::Val, RowMajorMatrix<T::Val>>>::ProverData;
    type Proof = <C::Pcs as Pcs<T::Val, RowMajorMatrix<T::Val>>>::Proof;
    type Error = <C::Pcs as Pcs<T::Val, RowMajorMatrix<T::Val>>>::Error;

    fn commit_batches(
        &self,
        polynomials: Vec<RowMajorMatrix<T::Val>>,
    ) -> (Self::Commitment, Self::ProverData) {
        self.pcs.commit_batches(polynomials)
    }

    fn commit_batch(
        &self,
        polynomials: RowMajorMatrix<T::Val>,
    ) -> (Self::Commitment, Self::ProverData) {
        self.commit_batches(std::vec![polynomials])
    }
}
