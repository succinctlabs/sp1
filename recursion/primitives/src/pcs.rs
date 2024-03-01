use itertools::izip;
use p3_challenger::{CanObserve, CanSample, FieldChallenger, GrindingChallenger};
use p3_commit::{DirectMmcs, Mmcs, Pcs, UnivariatePcs, UnivariatePcsWithLde};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{AbstractExtensionField, AbstractField, ExtensionField, PrimeField32, TwoAdicField};
use p3_fri::{
    verifier, FriConfig, TwoAdicFriPcs, TwoAdicFriPcsConfig, TwoAdicFriPcsGenericConfig,
    VerificationError,
};
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixView};
use p3_util::{log2_strict_usize, reverse_bits_len};

extern "C" {
    fn syscall_fri_fold(input_mem_ptr: *const u32, output_mem_ptr: *const *mut u32);
}

pub(crate) trait TwoAdicPrime32FriPcsGenericConfig: TwoAdicFriPcsGenericConfig {
    type Prime32Val: TwoAdicField + PrimeField32;
    type Prime32Challenge: TwoAdicField + ExtensionField<Self::Prime32Val>;
    type ChallengerPrime32: FieldChallenger<Self::Val>
        + GrindingChallenger<Witness = Self::Val>
        + CanObserve<<Self::FriMmcs as Mmcs<Self::Challenge>>::Commitment>
        + CanSample<Self::Challenge>
        + CanSample<Self::Prime32Challenge>;
}

pub(crate) struct RecursiveTwoAdicFriPCS<C: TwoAdicPrime32FriPcsGenericConfig> {
    fri: FriConfig<C::FriMmcs>,
    dft: C::Dft,
    mmcs: C::InputMmcs,
    pcs: TwoAdicFriPcs<C>,
}

impl<C: TwoAdicPrime32FriPcsGenericConfig> RecursiveTwoAdicFriPCS<C> {
    pub const fn new(fri: FriConfig<C::FriMmcs>, dft: C::Dft, mmcs: C::InputMmcs) -> Self {
        let plonky3_pcs = TwoAdicFriPcs::new(fri, dft, mmcs);
        Self {
            fri,
            dft,
            mmcs,
            pcs: plonky3_pcs,
        }
    }
}

impl<Val, Challenge, Challenger, Dft, InputMmcs, FriMmcs> TwoAdicPrime32FriPcsGenericConfig
    for TwoAdicFriPcsConfig<Val, Challenge, Challenger, Dft, InputMmcs, FriMmcs>
where
    Val: TwoAdicField + PrimeField32,
    Challenge: TwoAdicField + ExtensionField<Val>,
    Challenger: FieldChallenger<Val>
        + GrindingChallenger<Witness = Val>
        + CanObserve<<FriMmcs as Mmcs<Challenge>>::Commitment>
        + CanSample<Challenge>,
    Dft: TwoAdicSubgroupDft<Val>,
    InputMmcs: 'static + for<'a> DirectMmcs<Val, Mat<'a> = RowMajorMatrixView<'a, Val>>,
    FriMmcs: DirectMmcs<Challenge>,
{
    type Prime32Val = Val;
    type Prime32Challenge = Challenge;
    type ChallengerPrime32 = Challenger;
}

impl<C: TwoAdicPrime32FriPcsGenericConfig>
    UnivariatePcsWithLde<C::Val, C::Challenge, RowMajorMatrix<C::Val>, C::ChallengerPrime32>
    for RecursiveTwoAdicFriPCS<C>
{
    type Lde<'a> = <TwoAdicFriPcs<C> as UnivariatePcsWithLde<
        C::Val,
        C::Challenge,
        RowMajorMatrix<C::Val>,
        C::Challenger,
    >>::Lde<'a> where C: 'a;

    fn coset_shift(&self) -> C::Val {
        <TwoAdicFriPcs<C> as UnivariatePcsWithLde<
            C::Val,
            C::Challenge,
            RowMajorMatrix<C::Val>,
            C::Challenger,
        >>::coset_shift(&self.pcs)
    }

    fn log_blowup(&self) -> usize {
        <TwoAdicFriPcs<C> as UnivariatePcsWithLde<
            C::Val,
            C::Challenge,
            RowMajorMatrix<C::Val>,
            C::Challenger,
        >>::log_blowup(&self.pcs)
    }

    fn get_ldes<'a, 'b>(&'a self, prover_data: &'b Self::ProverData) -> Vec<Self::Lde<'b>>
    where
        'a: 'b,
    {
        <TwoAdicFriPcs<C> as UnivariatePcsWithLde<
            C::Val,
            C::Challenge,
            RowMajorMatrix<C::Val>,
            C::Challenger,
        >>::get_ldes(&self.pcs, prover_data)
    }

    fn commit_shifted_batches(
        &self,
        polynomials: Vec<RowMajorMatrix<C::Val>>,
        coset_shift: &[C::Val],
    ) -> (Self::Commitment, Self::ProverData) {
        self.pcs.commit_shifted_batches(polynomials, coset_shift)
    }

    fn commit_shifted_batch(
        &self,
        polynomials: RowMajorMatrix<C::Val>,
        coset_shift: C::Val,
    ) -> (Self::Commitment, Self::ProverData) {
        self.pcs.commit_shifted_batch(polynomials, coset_shift)
    }
}

impl<C: TwoAdicPrime32FriPcsGenericConfig>
    UnivariatePcs<C::Val, C::Challenge, RowMajorMatrix<C::Val>, C::ChallengerPrime32>
    for RecursiveTwoAdicFriPCS<C>
{
    fn open_multi_batches(
        &self,
        prover_data_and_points: &[(&Self::ProverData, &[Vec<C::Challenge>])],
        challenger: &mut C::ChallengerPrime32,
    ) -> (p3_commit::OpenedValues<C::Challenge>, Self::Proof) {
        <TwoAdicFriPcs<C> as UnivariatePcs<
            C::Val,
            C::Challenge,
            RowMajorMatrix<C::Val>,
            C::Challenger,
        >>::open_multi_batches(&self.pcs, prover_data_and_points, challenger)
    }

    fn verify_multi_batches(
        &self,
        commits_and_points: &[(Self::Commitment, &[Vec<C::Challenge>])],
        dims: &[Vec<p3_matrix::Dimensions>],
        values: p3_commit::OpenedValues<C::Challenge>,
        proof: &Self::Proof,
        challenger: &mut C::ChallengerPrime32,
    ) -> Result<(), Self::Error> {
        // Batch combination challenge
        let alpha = <C::ChallengerPrime32 as CanSample<C::Prime32Challenge>>::sample(challenger);

        let fri_challenges =
            verifier::verify_shape_and_sample_challenges(&self.fri, &proof.fri_proof, challenger)
                .map_err(VerificationError::FriError)?;

        let log_max_height = proof.fri_proof.commit_phase_commits.len() + self.fri.log_blowup;

        let reduced_openings: Vec<[C::Challenge; 32]> = proof
            .query_openings
            .iter()
            .zip(&fri_challenges.query_indices)
            .map(|(query_opening, &index)| {
                let mut ro = [C::Challenge::zero(); 32];
                let mut alpha_pow = [C::Challenge::one(); 32];
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
                        let x = C::Prime32Val::generator()
                            * C::Prime32Val::two_adic_generator(log_height)
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
            .collect::<Result<Vec<_>, <C::InputMmcs as Mmcs<C::Val>>::Error>>()
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

impl<T: TwoAdicPrime32FriPcsGenericConfig> Pcs<T::Val, RowMajorMatrix<T::Val>>
    for RecursiveTwoAdicFriPCS<T>
{
    type Commitment = <TwoAdicFriPcs<T> as Pcs<T::Val, RowMajorMatrix<T::Val>>>::Commitment;
    type ProverData = <TwoAdicFriPcs<T> as Pcs<T::Val, RowMajorMatrix<T::Val>>>::ProverData;
    type Proof = <TwoAdicFriPcs<T> as Pcs<T::Val, RowMajorMatrix<T::Val>>>::Proof;
    type Error = <TwoAdicFriPcs<T> as Pcs<T::Val, RowMajorMatrix<T::Val>>>::Error;

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
