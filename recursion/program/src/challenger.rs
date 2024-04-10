use p3_field::AbstractField;

use sp1_recursion_compiler::prelude::{Array, Builder, Config, Ext, Felt, Usize, Var};
use sp1_recursion_core::runtime::{DIGEST_SIZE, PERMUTATION_WIDTH};

use crate::fri::types::DigestVariable;

pub trait CanObserveVariable<C: Config, V> {
    fn observe(&mut self, builder: &mut Builder<C>, value: V);

    fn observe_slice(&mut self, builder: &mut Builder<C>, values: &[V])
    where
        V: Copy,
    {
        for value in values {
            self.observe(builder, *value);
        }
    }
}

pub trait CanSampleVariable<C: Config, V> {
    fn sample(&mut self, builder: &mut Builder<C>) -> V;
}

pub trait FeltChallenger<C: Config>:
    CanObserveVariable<C, Felt<C::F>> + CanSampleVariable<C, Felt<C::F>> + CanSampleBitsVariable<C>
{
    fn sample_ext(&mut self, builder: &mut Builder<C>) -> Ext<C::F, C::EF>;
}

pub trait CanSampleBitsVariable<C: Config> {
    fn sample_bits(
        &mut self,
        builder: &mut Builder<C>,
        nb_bits: Usize<C::N>,
    ) -> Array<C, Var<C::N>>;
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/challenger/src/duplex_challenger.rs#L10
#[derive(Clone)]
pub struct DuplexChallengerVariable<C: Config> {
    pub sponge_state: Array<C, Felt<C::F>>,
    pub nb_inputs: Var<C::N>,
    pub input_buffer: Array<C, Felt<C::F>>,
    pub nb_outputs: Var<C::N>,
    pub output_buffer: Array<C, Felt<C::F>>,
}

impl<C: Config> DuplexChallengerVariable<C> {
    pub fn new(builder: &mut Builder<C>) -> Self {
        DuplexChallengerVariable::<C> {
            sponge_state: builder.dyn_array(PERMUTATION_WIDTH),
            nb_inputs: builder.eval(C::N::zero()),
            input_buffer: builder.dyn_array(PERMUTATION_WIDTH),
            nb_outputs: builder.eval(C::N::zero()),
            output_buffer: builder.dyn_array(PERMUTATION_WIDTH),
        }
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/challenger/src/duplex_challenger.rs#L38
    pub fn duplexing(&mut self, builder: &mut Builder<C>) {
        builder.range(0, self.nb_inputs).for_each(|i, builder| {
            let element = builder.get(&self.input_buffer, i);
            builder.set(&mut self.sponge_state, i, element);
        });
        builder.assign(self.nb_inputs, C::N::zero());

        builder.poseidon2_permute_mut(&self.sponge_state);

        builder.assign(self.nb_outputs, C::N::zero());

        for i in 0..PERMUTATION_WIDTH {
            let element = builder.get(&self.sponge_state, i);
            builder.set(&mut self.output_buffer, i, element);
            builder.assign(self.nb_outputs, self.nb_outputs + C::N::one());
        }
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/challenger/src/duplex_challenger.rs#L61
    fn observe(&mut self, builder: &mut Builder<C>, value: Felt<C::F>) {
        builder.assign(self.nb_outputs, C::N::zero());

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
    fn observe_commitment(&mut self, builder: &mut Builder<C>, commitment: DigestVariable<C>) {
        for i in 0..DIGEST_SIZE {
            let element = builder.get(&commitment, i);
            self.observe(builder, element);
        }
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/challenger/src/duplex_challenger.rs#L124
    fn sample(&mut self, builder: &mut Builder<C>) -> Felt<C::F> {
        let zero: Var<_> = builder.eval(C::N::zero());
        builder.if_ne(self.nb_inputs, zero).then_or_else(
            |builder| {
                self.clone().duplexing(builder);
            },
            |builder| {
                builder.if_eq(self.nb_outputs, zero).then(|builder| {
                    self.clone().duplexing(builder);
                });
            },
        );
        let idx: Var<_> = builder.eval(self.nb_outputs - C::N::one());
        let output = builder.get(&self.output_buffer, idx);
        builder.assign(self.nb_outputs, self.nb_outputs - C::N::one());
        output
    }

    fn sample_ext(&mut self, builder: &mut Builder<C>) -> Ext<C::F, C::EF> {
        let a = self.sample(builder);
        let b = self.sample(builder);
        let c = self.sample(builder);
        let d = self.sample(builder);
        builder.ext_from_base_slice(&[a, b, c, d])
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/challenger/src/duplex_challenger.rs#L144
    fn sample_bits(
        &mut self,
        builder: &mut Builder<C>,
        nb_bits: Usize<C::N>,
    ) -> Array<C, Var<C::N>> {
        let rand_f = self.sample(builder);
        let mut bits = builder.num2bits_f(rand_f);

        builder.range(nb_bits, bits.len()).for_each(|i, builder| {
            builder.set(&mut bits, i, C::N::zero());
        });

        bits
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/challenger/src/grinding_challenger.rs#L16
    pub fn check_witness(&mut self, builder: &mut Builder<C>, nb_bits: usize, witness: Felt<C::F>) {
        self.observe(builder, witness);
        let element_bits = self.sample_bits(builder, Usize::Const(nb_bits));
        builder.range(0, nb_bits).for_each(|i, builder| {
            let element = builder.get(&element_bits, i);
            builder.assert_var_eq(element, C::N::zero());
        });
    }
}

impl<C: Config> CanObserveVariable<C, Felt<C::F>> for DuplexChallengerVariable<C> {
    fn observe(&mut self, builder: &mut Builder<C>, value: Felt<C::F>) {
        DuplexChallengerVariable::observe(self, builder, value);
    }
}

impl<C: Config> CanSampleVariable<C, Felt<C::F>> for DuplexChallengerVariable<C> {
    fn sample(&mut self, builder: &mut Builder<C>) -> Felt<C::F> {
        DuplexChallengerVariable::sample(self, builder)
    }
}

impl<C: Config> CanSampleBitsVariable<C> for DuplexChallengerVariable<C> {
    fn sample_bits(
        &mut self,
        builder: &mut Builder<C>,
        nb_bits: Usize<C::N>,
    ) -> Array<C, Var<C::N>> {
        DuplexChallengerVariable::sample_bits(self, builder, nb_bits)
    }
}

impl<C: Config> CanObserveVariable<C, DigestVariable<C>> for DuplexChallengerVariable<C> {
    fn observe(&mut self, builder: &mut Builder<C>, commitment: DigestVariable<C>) {
        DuplexChallengerVariable::observe_commitment(self, builder, commitment);
    }
}

impl<C: Config> FeltChallenger<C> for DuplexChallengerVariable<C> {
    fn sample_ext(&mut self, builder: &mut Builder<C>) -> Ext<C::F, C::EF> {
        DuplexChallengerVariable::sample_ext(self, builder)
    }
}

#[cfg(test)]
mod tests {
    use p3_challenger::CanObserve;
    use p3_challenger::CanSample;
    use p3_field::AbstractField;
    use p3_field::PrimeField32;
    use sp1_core::stark::StarkGenericConfig;
    use sp1_core::utils::BabyBearPoseidon2;
    use sp1_recursion_compiler::asm::AsmBuilder;
    use sp1_recursion_compiler::asm::AsmConfig;
    use sp1_recursion_compiler::ir::Felt;
    use sp1_recursion_compiler::ir::Usize;
    use sp1_recursion_compiler::ir::Var;
    use sp1_recursion_core::runtime::Runtime;
    use sp1_recursion_core::runtime::PERMUTATION_WIDTH;

    use crate::challenger::DuplexChallengerVariable;

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

        let mut builder = AsmBuilder::<F, EF>::default();

        let width: Var<_> = builder.eval(F::from_canonical_usize(PERMUTATION_WIDTH));
        let mut challenger = DuplexChallengerVariable::<AsmConfig<F, EF>> {
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

        let program = builder.compile_program();

        let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
        runtime.run();
        println!(
            "The program executed successfully, number of cycles: {}",
            runtime.clk.as_canonical_u32() / 4
        );
    }
}
