//! A duplex challenger for Poseidon2 over BN254.

use sp1_recursion_compiler::ir::{Builder, Config, Var};

use crate::poseidon2::P2CircuitBuilder;

pub struct DuplexChallengerVariable<C: Config> {
    sponge_state: [Var<C::N>; 3],
    input_buffer: Vec<Var<C::N>>,
    output_buffer: Vec<Var<C::N>>,
}

impl<C: Config> DuplexChallengerVariable<C> {
    pub fn duplexing(&mut self, builder: &mut Builder<C>) {
        for (i, val) in self.input_buffer.drain(..).enumerate() {
            self.sponge_state[i] = val;
        }

        builder.p2_permute_mut(self.sponge_state);

        self.output_buffer.clear();
        self.output_buffer.extend(self.sponge_state);
    }

    pub fn observe(&mut self, builder: &mut Builder<C>, value: Var<C::N>) {
        self.output_buffer.clear();

        self.input_buffer.push(value);
        if self.input_buffer.len() == 3 {
            self.duplexing(builder);
        }
    }

    pub fn sample(&mut self, builder: &mut Builder<C>) -> Var<C::N> {
        if !self.input_buffer.is_empty() || self.output_buffer.is_empty() {
            self.duplexing(builder);
        }

        self.output_buffer
            .pop()
            .expect("output buffer should be non-empty")
    }
}
