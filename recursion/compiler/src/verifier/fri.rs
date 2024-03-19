use super::types::FmtQueryProof;
use super::types::FriConfig;
use crate::builder;
use crate::prelude::Array;
use crate::prelude::Builder;
use crate::prelude::Config;
use crate::prelude::Felt;
use crate::prelude::Usize;
use crate::prelude::Var;
use crate::verifier::types::Hash;

use itertools::izip;
use p3_field::AbstractField;
use p3_field::TwoAdicField;
use p3_matrix::Dimensions;

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
        builder: &mut Builder<C>,
        config: &FriConfig,
        commit_phase_commits: &Array<C, Hash<C>>,
        mut index: usize,
        proof: &FmtQueryProof<C>,
        betas: &Array<C, Felt<C::F>>,
        reduced_openings: &Array<C, Felt<C::F>>,
        log_max_height: Usize<C::N>,
    ) where
        C::F: TwoAdicField,
    {
        let folded_eval: Felt<_> = builder.eval(C::F::zero());
        let generator = builder.two_adic_generator(Usize::Const(1));
        let two_adic_generator = builder.two_adic_generator(log_max_height);
        let power = builder.reverse_bits_len(Usize::Const(index), log_max_height);
        let x = builder.exp_usize(two_adic_generator, power);

        let start = Usize::Const(0);
        let end = log_max_height;
        let end_var: Var<C::N> = match log_max_height {
            Usize::Const(log_max_height) => {
                builder.eval(C::N::from_canonical_usize(log_max_height))
            }
            Usize::Var(log_max_height) => log_max_height,
        };

        builder.range(start, end).for_each(|i, builder| {
            let log_folded_height: Var<_> = builder.eval(end_var - i);
            let reduced_opening_term = builder.get(reduced_openings, log_folded_height);
            builder.assign(folded_eval, folded_eval + reduced_opening_term);

            let index_sibling = index ^ 1;
            let index_pair = index >> 1;

            let step = builder.get(&proof.commit_phase_openings, i);
            let mut evals = vec![folded_eval; 2];
            evals[index_sibling % 2] = step.sibling_value;

            // let dims = &[Dimensions {
            //     width: 2,
            //     height: (1 << log_folded_height),
            // }];
            // TODO: verify_batch(config, commit, step).

            let beta = builder.get(betas, i);
            let xs = [x; 2];
            builder.assign(xs[index_sibling % 2], xs[index_sibling % 2] * generator);
            builder.assign(
                folded_eval,
                evals[0] + (beta - xs[0]) * (evals[1] - evals[0]) / (xs[1] - xs[0]),
            );

            index = index_pair;
            builder.assign(x, x * x);
        });

        // debug_assert!(index < config.blowup(), "index was {}", index);
        // debug_assert_eq!(x.exp_power_of_2(config.log_blowup), F::one());
    }
}
