use super::types::FmtQueryProof;
use super::types::FriConfig;
use crate::prelude::Array;
use crate::prelude::Builder;
use crate::prelude::Config;
use crate::prelude::Felt;
use crate::prelude::Usize;
use crate::prelude::Var;
use crate::verifier::types::Hash;

use p3_field::AbstractField;
use p3_field::TwoAdicField;

impl<C: Config> Builder<C> {
    pub fn materialize(&mut self, num: Usize<C::N>) -> Var<C::N> {
        match num {
            Usize::Const(num) => self.eval(C::N::from_canonical_usize(num)),
            Usize::Var(num) => num,
        }
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/baby-bear/src/baby_bear.rs#L306
    pub fn generator(&mut self) -> Felt<C::F> {
        self.eval(C::F::from_canonical_u32(0x78000000))
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/baby-bear/src/baby_bear.rs#L302
    #[allow(unused_variables)]
    pub fn two_adic_generator(&mut self, bits: Usize<C::N>) -> Felt<C::F> {
        todo!()
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/util/src/lib.rs#L59
    #[allow(unused_variables)]
    pub fn reverse_bits_len(&mut self, index: Usize<C::N>, bit_len: Usize<C::N>) -> Usize<C::N> {
        todo!()
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/field/src/field.rs#L79
    #[allow(unused_variables)]
    pub fn exp_usize(&mut self, x: Felt<C::F>, power: Usize<C::N>) -> Felt<C::F> {
        todo!()
    }

    /// Verifies a FRI query.
    ///
    /// Currently assumes the index that is accessed is constant.
    ///
    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/verifier.rs#L101
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
        let two_adic_generator = builder.two_adic_generator(log_max_height);
        let power = builder.reverse_bits_len(Usize::Const(index), log_max_height);
        let x = builder.exp_usize(two_adic_generator, power);

        let start = Usize::Const(0);
        let end = log_max_height;
        let end_var = builder.materialize(end);
        builder.range(start, end).for_each(|i, builder| {
            let log_folded_height: Var<_> = builder.eval(end_var - i);
            let reduced_opening_term = builder.get(reduced_openings, log_folded_height);
            builder.assign(folded_eval, folded_eval + reduced_opening_term);

            let index_sibling = index ^ 1;
            let index_pair = index >> 1;

            let step = builder.get(&proof.commit_phase_openings, i);
            let mut evals = [folded_eval; 2];
            evals[index_sibling % 2] = step.sibling_value;

            // let dims = &[Dimensions {
            //     width: 2,
            //     height: (1 << log_folded_height),
            // }];
            // TODO: verify_batch(config, commit, step).

            let beta = builder.get(betas, i);
            let xs = [x; 2];
            let generator = builder.generator();
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
