use p3_field::AbstractField;
use sp1_recursion_compiler::prelude::{
    Array, Builder, Config, DslVariable, Ext, Felt, MemIndex, MemVariable, Ptr, Usize, Var,
    Variable,
};
use sp1_recursion_core::runtime::{DIGEST_SIZE, HASH_RATE, PERMUTATION_WIDTH};

use crate::{fri::types::DigestVariable, types::VerifyingKeyVariable};

/// Reference: [p3_challenger::CanObserve].
pub trait CanObserveVariable<C: Config, V> {
    fn observe(&mut self, builder: &mut Builder<C>, value: V);

    fn observe_slice(&mut self, builder: &mut Builder<C>, values: Array<C, V>);
}

pub trait CanSampleVariable<C: Config, V> {
    fn sample(&mut self, builder: &mut Builder<C>) -> V;
}

/// Reference: [p3_challenger::FieldChallenger].
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

/// Reference: [p3_challenger::DuplexChallenger]
#[derive(Clone, DslVariable)]
pub struct DuplexChallengerVariable<C: Config> {
    pub sponge_state: Array<C, Felt<C::F>>,
    pub nb_inputs: Var<C::N>,
    pub input_buffer: Array<C, Felt<C::F>>,
    pub nb_outputs: Var<C::N>,
    pub output_buffer: Array<C, Felt<C::F>>,
}

impl<C: Config> DuplexChallengerVariable<C> {
    /// Creates a new duplex challenger with the default state.
    pub fn new(builder: &mut Builder<C>) -> Self {
        let mut result = DuplexChallengerVariable::<C> {
            sponge_state: builder.dyn_array(PERMUTATION_WIDTH),
            nb_inputs: builder.eval(C::N::zero()),
            input_buffer: builder.dyn_array(PERMUTATION_WIDTH),
            nb_outputs: builder.eval(C::N::zero()),
            output_buffer: builder.dyn_array(PERMUTATION_WIDTH),
        };

        // Constrain the state of the challenger to contain all zeroes.
        builder.range(0, PERMUTATION_WIDTH).for_each(|i, builder| {
            builder.set(&mut result.sponge_state, i, C::F::zero());
            builder.set(&mut result.input_buffer, i, C::F::zero());
            builder.set(&mut result.output_buffer, i, C::F::zero());
        });
        result
    }

    /// Creates a new challenger with the same state as an existing challenger.
    pub fn copy(&self, builder: &mut Builder<C>) -> Self {
        let mut sponge_state = builder.dyn_array(PERMUTATION_WIDTH);
        builder.range(0, PERMUTATION_WIDTH).for_each(|i, builder| {
            let element = builder.get(&self.sponge_state, i);
            builder.set(&mut sponge_state, i, element);
        });
        let nb_inputs = builder.eval(self.nb_inputs);
        let mut input_buffer = builder.dyn_array(PERMUTATION_WIDTH);
        builder.range(0, PERMUTATION_WIDTH).for_each(|i, builder| {
            let element = builder.get(&self.input_buffer, i);
            builder.set(&mut input_buffer, i, element);
        });
        let nb_outputs = builder.eval(self.nb_outputs);
        let mut output_buffer = builder.dyn_array(PERMUTATION_WIDTH);
        builder.range(0, PERMUTATION_WIDTH).for_each(|i, builder| {
            let element = builder.get(&self.output_buffer, i);
            builder.set(&mut output_buffer, i, element);
        });
        DuplexChallengerVariable::<C> {
            sponge_state,
            nb_inputs,
            input_buffer,
            nb_outputs,
            output_buffer,
        }
    }

    /// Asserts that the state of this challenger is equal to the state of another challenger.
    pub fn assert_eq(&self, builder: &mut Builder<C>, other: &Self) {
        builder.assert_var_eq(self.nb_inputs, other.nb_inputs);
        builder.assert_var_eq(self.nb_outputs, other.nb_outputs);
        builder.range(0, PERMUTATION_WIDTH).for_each(|i, builder| {
            let element = builder.get(&self.sponge_state, i);
            let other_element = builder.get(&other.sponge_state, i);
            builder.assert_felt_eq(element, other_element);
        });
        builder.range(0, self.nb_inputs).for_each(|i, builder| {
            let element = builder.get(&self.input_buffer, i);
            let other_element = builder.get(&other.input_buffer, i);
            builder.assert_felt_eq(element, other_element);
        });
        builder.range(0, self.nb_outputs).for_each(|i, builder| {
            let element = builder.get(&self.output_buffer, i);
            let other_element = builder.get(&other.output_buffer, i);
            builder.assert_felt_eq(element, other_element);
        });
    }

    pub fn reset(&mut self, builder: &mut Builder<C>) {
        let zero: Var<_> = builder.eval(C::N::zero());
        let zero_felt: Felt<_> = builder.eval(C::F::zero());
        builder.range(0, PERMUTATION_WIDTH).for_each(|i, builder| {
            builder.set(&mut self.sponge_state, i, zero_felt);
        });
        builder.assign(self.nb_inputs, zero);
        builder.range(0, PERMUTATION_WIDTH).for_each(|i, builder| {
            builder.set(&mut self.input_buffer, i, zero_felt);
        });
        builder.assign(self.nb_outputs, zero);
        builder.range(0, PERMUTATION_WIDTH).for_each(|i, builder| {
            builder.set(&mut self.output_buffer, i, zero_felt);
        });
    }

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

    fn observe(&mut self, builder: &mut Builder<C>, value: Felt<C::F>) {
        builder.assign(self.nb_outputs, C::N::zero());

        builder.set(&mut self.input_buffer, self.nb_inputs, value);
        builder.assign(self.nb_inputs, self.nb_inputs + C::N::one());

        builder.if_eq(self.nb_inputs, C::N::from_canonical_usize(HASH_RATE)).then(|builder| {
            self.duplexing(builder);
        })
    }

    fn observe_commitment(&mut self, builder: &mut Builder<C>, commitment: DigestVariable<C>) {
        for i in 0..DIGEST_SIZE {
            let element = builder.get(&commitment, i);
            self.observe(builder, element);
        }
    }

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

    pub fn check_witness(
        &mut self,
        builder: &mut Builder<C>,
        nb_bits: Var<C::N>,
        witness: Felt<C::F>,
    ) {
        self.observe(builder, witness);
        let element_bits = self.sample_bits(builder, nb_bits.into());
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

    fn observe_slice(&mut self, builder: &mut Builder<C>, values: Array<C, Felt<C::F>>) {
        match values {
            Array::Dyn(_, len) => {
                builder.range(0, len).for_each(|i, builder| {
                    let element = builder.get(&values, i);
                    self.observe(builder, element);
                });
            }
            Array::Fixed(values) => {
                values.iter().for_each(|value| {
                    self.observe(builder, *value);
                });
            }
        }
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

    fn observe_slice(&mut self, _builder: &mut Builder<C>, _values: Array<C, DigestVariable<C>>) {
        todo!()
    }
}

impl<C: Config> CanObserveVariable<C, VerifyingKeyVariable<C>> for DuplexChallengerVariable<C> {
    fn observe(&mut self, builder: &mut Builder<C>, value: VerifyingKeyVariable<C>) {
        self.observe_commitment(builder, value.commitment);
        self.observe(builder, value.pc_start)
    }

    fn observe_slice(
        &mut self,
        _builder: &mut Builder<C>,
        _values: Array<C, VerifyingKeyVariable<C>>,
    ) {
        todo!()
    }
}

impl<C: Config> FeltChallenger<C> for DuplexChallengerVariable<C> {
    fn sample_ext(&mut self, builder: &mut Builder<C>) -> Ext<C::F, C::EF> {
        DuplexChallengerVariable::sample_ext(self, builder)
    }
}

#[cfg(test)]
mod tests {
    use p3_challenger::{CanObserve, CanSample};
    use p3_field::AbstractField;

    use sp1_recursion_compiler::{
        asm::{AsmBuilder, AsmConfig},
        ir::{Felt, Usize, Var},
    };

    use sp1_recursion_core::{
        runtime::PERMUTATION_WIDTH,
        stark::utils::{run_test_recursion, TestConfig},
    };
    use sp1_stark::{baby_bear_poseidon2::BabyBearPoseidon2, StarkGenericConfig};

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
        builder.halt();
        challenger.observe(&mut builder, one);
        challenger.observe(&mut builder, two);
        challenger.observe(&mut builder, two);
        challenger.observe(&mut builder, two);
        let element = challenger.sample(&mut builder);

        let expected_result: Felt<_> = builder.eval(result);
        builder.assert_felt_eq(expected_result, element);

        let program = builder.compile_program();
        run_test_recursion(program, None, TestConfig::All);
    }
}
