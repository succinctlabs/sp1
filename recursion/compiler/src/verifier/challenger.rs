use p3_field::AbstractField;

use super::types::{Commitment, PERMUTATION_WIDTH};
use crate::prelude::{Array, Builder, Config, Felt, MemVariable, Usize, Var};

pub struct DuplexChallenger<C: Config> {
    pub sponge_state: Array<C, Felt<C::F>>,
    pub nb_inputs: Var<C::N>,
    pub input_buffer: Array<C, Felt<C::F>>,
    pub nb_outputs: Var<C::N>,
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
            builder.assign(self.nb_outputs, self.nb_outputs + C::N::one());
        });
        builder.assign(self.nb_inputs, C::N::zero());

        builder.poseidon2_permute(&self.sponge_state);

        builder.clear(self.output_buffer.clone());
        builder.range(start, end).for_each(|i, builder| {
            let element = builder.get(&self.sponge_state, i);
            builder.set(&mut self.output_buffer, i, element);
        });
    }

    pub fn observe(&mut self, builder: &mut Builder<C>, value: Felt<C::F>) {
        builder.clear(self.output_buffer.clone());

        builder.set(&mut self.input_buffer, self.nb_inputs, value);
        builder.assign(self.nb_inputs, self.nb_inputs + C::N::one());

        builder
            .if_eq(
                self.nb_inputs,
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

    pub fn sample(&mut self, builder: &mut Builder<C>) -> Felt<C::F> {
        let zero: Var<_> = builder.eval(C::N::zero());
        builder
            .if_ne(self.nb_inputs + self.nb_outputs, zero)
            .then(|builder| {
                self.duplexing(builder);
            });
        let idx: Var<_> = builder.eval(self.nb_outputs - C::N::one());
        let output = builder.get(&self.output_buffer, idx);
        builder.assign(self.nb_outputs, self.nb_outputs - C::N::one());
        output
    }

    pub fn sample_bits(&mut self, builder: &mut Builder<C>, nb_bits: Usize<C::N>) -> Var<C::N> {
        let rand_f = self.sample(builder);
        let bits = builder.num2bits_f(rand_f);
        let start = Usize::Const(0);
        let end = nb_bits;
        let sum: Var<C::N> = builder.eval(C::N::zero());
        let power: Var<C::N> = builder.eval(C::N::from_canonical_usize(1));
        builder.range(start, end).for_each(|i, builder| {
            let bit = builder.get(&bits, i);
            builder.assign(self.nb_outputs, bit);
            builder.assign(sum, power * sum);
            builder.assign(power, power * C::N::from_canonical_usize(2));
        });
        sum
    }
}
