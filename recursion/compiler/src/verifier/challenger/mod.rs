pub mod utils;

use p3_field::AbstractField;

use crate::prelude::{Array, Builder, Config, Felt, Usize, Var};
use crate::verifier::fri::types::Commitment;
use crate::verifier::fri::types::PERMUTATION_WIDTH;

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/challenger/src/duplex_challenger.rs#L10
pub struct DuplexChallenger<C: Config> {
    pub sponge_state: Array<C, Felt<C::F>>,
    pub nb_inputs: Var<C::N>,
    pub input_buffer: Array<C, Felt<C::F>>,
    pub nb_outputs: Var<C::N>,
    pub output_buffer: Array<C, Felt<C::F>>,
}

impl<C: Config> DuplexChallenger<C> {
    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/challenger/src/duplex_challenger.rs#L38
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

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/challenger/src/duplex_challenger.rs#L61
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

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/challenger/src/duplex_challenger.rs#L78
    pub fn observe_commitment(&mut self, builder: &mut Builder<C>, commitment: Commitment<C>) {
        let start = Usize::Const(0);
        let end = commitment.len();
        builder.range(start, end).for_each(|i, builder| {
            let element = builder.get(&commitment, i);
            self.observe(builder, element);
        });
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/challenger/src/duplex_challenger.rs#L124
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

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/challenger/src/duplex_challenger.rs#L144
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

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/challenger/src/grinding_challenger.rs#L16
    pub fn check_witness(
        &mut self,
        builder: &mut Builder<C>,
        nb_bits: Var<C::N>,
        witness: Felt<C::F>,
    ) {
        self.observe(builder, witness);
        let element = self.sample_bits(builder, Usize::Var(nb_bits));
        builder
            .if_eq(element, C::N::one())
            .then(|builder| builder.error());
    }
}

#[cfg(test)]
mod tests {

    use crate::asm::AsmConfig;
    use crate::asm::VmBuilder;
    use crate::ir::Felt;
    use crate::ir::Usize;
    use crate::ir::Var;
    use crate::verifier::challenger::DuplexChallenger;
    use p3_challenger::CanObserve;
    use p3_challenger::CanSample;
    use p3_field::AbstractField;
    use p3_field::PrimeField32;
    use sp1_core::stark::StarkGenericConfig;
    use sp1_core::utils::BabyBearPoseidon2;
    use sp1_recursion_core::runtime::Runtime;
    use sp1_recursion_core::runtime::POSEIDON2_WIDTH;

    #[test]
    fn test_compiler_challenger() {
        type SC = BabyBearPoseidon2;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;

        let config = SC::default();
        let mut challenger = config.challenger();
        challenger.observe(F::one());
        challenger.observe(F::two());
        challenger.observe(F::two());
        challenger.observe(F::two());
        let result: F = challenger.sample();
        println!("expected result: {}", result);

        let mut builder = VmBuilder::<F, EF>::default();

        let width: Var<_> = builder.eval(F::from_canonical_usize(POSEIDON2_WIDTH));
        let mut challenger = DuplexChallenger::<AsmConfig<F, EF>> {
            sponge_state: builder.array(Usize::Var(width)),
            nb_inputs: builder.eval(F::zero()),
            input_buffer: builder.array(Usize::Var(width)),
            nb_outputs: builder.eval(F::zero()),
            output_buffer: builder.array(Usize::Var(width)),
        };
        let one: Felt<_> = builder.eval(F::one());
        let two: Felt<_> = builder.eval(F::two());
        challenger.observe(&mut builder, one);
        challenger.observe(&mut builder, two);
        challenger.observe(&mut builder, two);
        challenger.observe(&mut builder, two);
        let element = challenger.sample(&mut builder);

        let expected_result: Felt<_> = builder.eval(result);
        builder.assert_felt_eq(expected_result, element);

        let program = builder.compile();

        let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
        runtime.run();
        println!(
            "The program executed successfully, number of cycles: {}",
            runtime.clk.as_canonical_u32() / 4
        );
    }
}
