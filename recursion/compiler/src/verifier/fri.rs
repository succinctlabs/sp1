use std::marker::PhantomData;

use crate::prelude::Builder;
use crate::prelude::Config;
use crate::prelude::Felt;
use itertools::izip;
use p3_field::AbstractField;
use p3_field::TwoAdicField;
use p3_matrix::Dimensions;
use p3_util::reverse_bits_len;

pub const DIGEST_SIZE: usize = 8;

#[allow(type_alias_bounds)]
type Hash<C: Config> = [Felt<C::F>; DIGEST_SIZE];

pub struct FriConfig {
    pub log_blowup: usize,
    pub num_queries: usize,
    pub proof_of_work_bits: usize,
}

pub struct FmtQueryProof<C: Config> {
    pub commit_phase_openings: Vec<FmtCommitPhaseProofStep<C>>,
    pub phantom: PhantomData<C>,
}

pub struct FmtCommitPhaseProofStep<C: Config> {
    pub sibling_value: Felt<C::F>,
    pub opening_proof: Vec<Hash<C>>,
    pub phantom: PhantomData<C>,
}

impl<C: Config> Builder<C> {
    /// Verifies a FRI query.
    ///
    /// Currently assumes the index and log_max_height are constants.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_query(
        &mut self,
        config: &FriConfig,
        commit_phase_commits: &[Hash<C>],
        mut index: usize,
        proof: &FmtQueryProof<C>,
        betas: &[Felt<C::F>],
        reduced_openings: &[Felt<C::F>; 32],
        log_max_height: usize,
    ) where
        C::F: TwoAdicField,
    {
        let folded_eval: Felt<_> = self.eval(C::F::zero());
        let mut x = C::F::two_adic_generator(log_max_height)
            .exp_u64(reverse_bits_len(index, log_max_height) as u64);

        for (log_folded_height, commit, step, &beta) in izip!(
            (0..log_max_height).rev(),
            commit_phase_commits,
            &proof.commit_phase_openings,
            betas
        ) {
            self.assign(
                folded_eval,
                folded_eval + reduced_openings[log_folded_height + 1],
            );

            let index_sibling = index ^ 1;
            let index_pair = index >> 1;

            let mut evals = vec![folded_eval; 2];
            evals[index_sibling % 2] = step.sibling_value;

            let dims = &[Dimensions {
                width: 2,
                height: (1 << log_folded_height),
            }];

            // TODO: verify_batch(config, commit, step).

            let mut xs = [x; 2];
            xs[index_sibling % 2] *= C::F::two_adic_generator(1);
            self.assign(
                folded_eval,
                evals[0] + (beta - xs[0]) * (evals[1] - evals[0]) / (xs[1] - xs[0]),
            );

            index = index_pair;
            x = x.square();
        }

        // debug_assert!(index < config.blowup(), "index was {}", index);
        // debug_assert_eq!(x.exp_power_of_2(config.log_blowup), F::one());
    }
}
