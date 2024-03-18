use crate::prelude::Builder;
use crate::prelude::Config;
use crate::prelude::Felt;
use crate::prelude::Usize;
use crate::verifier::types::Hash;
use itertools::izip;
use p3_field::AbstractField;
use p3_field::TwoAdicField;
use p3_matrix::Dimensions;
use p3_util::reverse_bits_len;

use super::types::FmtQueryProof;
use super::types::FriConfig;

impl<C: Config> Builder<C> {
    pub fn two_adic_generator(&mut self, bits: Usize<C::N>) -> Felt<C::F> {
        todo!()
    }

    pub fn reverse_bits_len(&mut self, index: Usize<C::N>, bit_len: Usize<C::N>) -> Usize<C::N> {
        todo!()
    }

    pub fn exp_usize(&mut self, x: Felt<C::F>, power: Usize<C::N>) -> Felt<C::F> {
        todo!()
    }

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
        let generator = self.two_adic_generator(Usize::Const(1));
        let two_adic_generator = self.two_adic_generator(Usize::Const(log_max_height));
        let power = self.reverse_bits_len(Usize::Const(index), Usize::Const(log_max_height));
        let x = self.exp_usize(two_adic_generator, power);

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

            let xs = [x; 2];
            self.assign(xs[index_sibling % 2], xs[index_sibling % 2] * generator);
            self.assign(
                folded_eval,
                evals[0] + (beta - xs[0]) * (evals[1] - evals[0]) / (xs[1] - xs[0]),
            );

            index = index_pair;
            self.assign(x, x * x);
        }

        // debug_assert!(index < config.blowup(), "index was {}", index);
        // debug_assert_eq!(x.exp_power_of_2(config.log_blowup), F::one());
    }
}
