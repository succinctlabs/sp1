use crate::prelude::{Array, Builder, Config, Felt, MemVariable, Usize, Var};
use p3_field::AbstractField;

use super::types::{Commitment, PERMUTATION_WIDTH};

pub struct DuplexChallenger<C: Config> {
    pub nb_observed: Var<C::N>,
    pub sponge_state: Array<C, Felt<C::F>>,
    pub input_buffer: Array<C, Felt<C::F>>,
    pub output_buffer: Array<C, Felt<C::F>>,
}

impl<C: Config> Builder<C> {
    pub fn clear<V: MemVariable<C>>(&mut self, array: Array<C, V>) {
        let empty = self.array::<V, _>(array.len());
        self.assign(array.clone(), empty);
    }
}

impl<C: Config> DuplexChallenger<C> {
    pub fn duplexing(&mut self, builder: &mut Builder<C>) {
        let start = Usize::Const(0);
        let end = self.input_buffer.len();
        builder.range(start, end).for_each(|i, builder| {
            let element = builder.get(&self.input_buffer, i);
            builder.set(&mut self.sponge_state, i, element);
        });

        builder.poseidon2_permute(&self.sponge_state);

        builder.clear(self.output_buffer.clone());
        builder.range(start, end).for_each(|i, builder| {
            let element = builder.get(&self.sponge_state, i);
            builder.set(&mut self.output_buffer, i, element);
        });
    }

    pub fn observe(&mut self, builder: &mut Builder<C>, value: Felt<C::F>) {
        builder.clear(self.output_buffer.clone());

        builder.set(&mut self.input_buffer, self.nb_observed, value);
        builder.assign(self.nb_observed, self.nb_observed + C::N::one());

        builder
            .if_eq(
                self.nb_observed,
                C::N::from_canonical_usize(PERMUTATION_WIDTH),
            )
            .then(|builder| {
                self.duplexing(builder);
            })
    }

    pub fn observe_commitment(&mut self, builder: &mut Builder<C>, commitment: Commitment<C>) {
        let start = Usize::Const(0);
        let end = commitment.len();
        builder.range(start, end).for_each(|i, builder| {
            let element = builder.get(&commitment, i);
            self.observe(builder, element);
        });
    }
}
