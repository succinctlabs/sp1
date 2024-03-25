use sp1_recursion_compiler::ir::{Builder, Config, Felt};
use sp1_recursion_core::runtime::POSEIDON2_WIDTH;

use crate::poseidon2::Poseidon2CircuitBuilder;

pub struct DuplexChallengerVariable<C: Config> {
    sponge_state: [Felt<C::F>; POSEIDON2_WIDTH],
    input_buffer: Vec<Felt<C::F>>,
    output_buffer: Vec<Felt<C::F>>,
}

impl<C: Config> DuplexChallengerVariable<C> {
    pub fn duplexing(&mut self, builder: &mut Builder<C>) {
        for (i, val) in self.input_buffer.drain(..).enumerate() {
            self.sponge_state[i] = val;
        }

        builder.p2_permute_mut(&mut self.sponge_state);

        self.output_buffer.clear();
        self.output_buffer.extend(self.sponge_state);
    }

    pub fn observe(&mut self, builder: &mut Builder<C>, value: Felt<C::F>) {
        self.output_buffer.clear();

        self.input_buffer.push(value);
        if self.input_buffer.len() == POSEIDON2_WIDTH {
            self.duplexing(builder);
        }
    }

    pub fn sample(&mut self, builder: &mut Builder<C>) -> Felt<C::F> {
        if !self.input_buffer.is_empty() || self.output_buffer.is_empty() {
            self.duplexing(builder);
        }

        self.output_buffer
            .pop()
            .expect("output buffer should be non-empty")
    }
}
