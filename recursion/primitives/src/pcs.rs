use itertools::izip;
use p3_challenger::CanSample;
use p3_commit::{Mmcs, Pcs, UnivariatePcs, UnivariatePcsWithLde};
use p3_field::{AbstractField, TwoAdicField};
use p3_fri::{verifier, FriConfig, TwoAdicFriPcs, TwoAdicFriPcsGenericConfig, VerificationError};
use p3_matrix::dense::RowMajorMatrix;
use p3_util::{log2_strict_usize, reverse_bits_len};
use sp1_core::stark::StarkGenericConfig;

pub(crate) struct RecursiveTwoAdicFriPCS<
    C: StarkGenericConfig<Pcs = TwoAdicFriPcs<T>>,
    T: TwoAdicFriPcsGenericConfig,
> {
    fri: FriConfig<T::FriMmcs>,
    dft: T::Dft,
    mmcs: T::InputMmcs,
    pcs: C::Pcs,
}

impl<C: StarkGenericConfig<Pcs = TwoAdicFriPcs<T>>, T: TwoAdicFriPcsGenericConfig>
    RecursiveTwoAdicFriPCS<C, T>
{
    pub const fn new(fri: FriConfig<T::FriMmcs>, dft: T::Dft, mmcs: T::InputMmcs) -> Self {
        let plonky3_pcs = TwoAdicFriPcs::new(fri, dft, mmcs);
        Self {
            fri,
            dft,
            mmcs,
            pcs: plonky3_pcs,
        }
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
        self.pcs.commit_shifted_batch(polynomials, coset_shift)
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
        // Batch combination challenge
        let alpha = <T::Challenger as CanSample<T::Challenge>>::sample(challenger);

        let fri_challenges =
            verifier::verify_shape_and_sample_challenges(&self.fri, &proof.fri_proof, challenger)
                .map_err(VerificationError::FriError)?;

        let log_max_height = proof.fri_proof.commit_phase_commits.len() + self.fri.log_blowup;

        let reduced_openings: Vec<[T::Challenge; 32]> = proof
            .query_openings
            .iter()
            .zip(&fri_challenges.query_indices)
            .map(|(query_opening, &index)| {
                let mut ro = [T::Challenge::zero(); 32];
                let mut alpha_pow = [T::Challenge::one(); 32];
                for (batch_opening, batch_dims, (batch_commit, batch_points), batch_at_z) in
                    izip!(query_opening, dims, commits_and_points, &values)
                {
                    self.mmcs.verify_batch(
                        batch_commit,
                        batch_dims,
                        index,
                        &batch_opening.opened_values,
                        &batch_opening.opening_proof,
                    )?;
                    for (mat_opening, mat_dims, mat_points, mat_at_z) in izip!(
                        &batch_opening.opened_values,
                        batch_dims,
                        *batch_points,
                        batch_at_z
                    ) {
                        let log_height = log2_strict_usize(mat_dims.height) + self.fri.log_blowup;

                        let bits_reduced = log_max_height - log_height;
                        let rev_reduced_index = reverse_bits_len(index >> bits_reduced, log_height);

                        // A field mul with (field lookup then field exp)
                        let x = T::Val::generator()
                            * T::Val::two_adic_generator(log_height)
                                .exp_u64(rev_reduced_index as u64);

                        let mut array_arg: [u32; 14] = [0u32; 14];
                        let mut array_idx = 0;
                        array_arg[array_idx] = x.as_canonical_u32();
                        alpha.as_base_slice().iter().for_each(|x| {
                            array_idx += 1;
                            array_arg[array_idx] = x.as_canonical_u32();
                        });

                        let save_arg: [*mut u32; 2] = [
                            ro[log_height].as_base_slice_mut() as *mut u32,
                            alpha_pow[log_height].as_base_slice_mut() as *mut u32,
                        ];

                        for (&z, ps_at_z) in izip!(mat_points, mat_at_z) {
                            #[allow(clippy::never_loop)]
                            for (&p_at_x, &p_at_z) in izip!(mat_opening, ps_at_z) {
                                let mut idx = array_idx;
                                z.as_base_slice().iter().for_each(|x| {
                                    idx += 1;
                                    array_arg[idx] = x.as_canonical_u32();
                                });
                                p_at_z.as_base_slice().iter().for_each(|x| {
                                    idx += 1;
                                    array_arg[idx] = x.as_canonical_u32();
                                });
                                idx += 1;
                                array_arg[idx] = p_at_x.as_canonical_u32();

                                unsafe {
                                    syscall_fri_fold((&array_arg).as_ptr(), (&save_arg).as_ptr());
                                }
                            }
                        }
                    }
                }
                Ok(ro)
            })
            .collect::<Result<Vec<_>, <T::InputMmcs as Mmcs<T::Val>>::Error>>()
            .map_err(VerificationError::InputMmcsError)?;

        verifier::verify_challenges(
            &self.fri,
            &proof.fri_proof,
            &fri_challenges,
            &reduced_openings,
        )
        .map_err(VerificationError::FriError)?;

        Ok(())
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
        self.pcs.commit_batch(polynomials)
    }
}
