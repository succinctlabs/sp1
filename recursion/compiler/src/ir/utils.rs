use p3_field::AbstractField;
use std::ops::MulAssign;

use super::{Builder, Config, DslIR, Felt, Var, Variable};

impl<C: Config> Builder<C> {
    pub fn exp_power_of_2<V: Variable<C>, E: Into<V::Expression>>(
        &mut self,
        e: E,
        power_log: usize,
    ) -> V
    where
        V::Expression: MulAssign<V::Expression> + Clone,
    {
        let mut e = e.into();
        for _ in 0..power_log {
            e *= e.clone();
        }
        self.eval(e)
    }

    pub fn num2bits_f_circuit(&mut self, num: Felt<C::F>) -> Vec<Var<C::N>> {
        let mut output = Vec::new();
        for _ in 0..32 {
            output.push(self.uninit());
        }

        self.operations
            .push(DslIR::CircuitNum2BitsF(num, output.clone()));

        output
    }

    pub fn bits_to_num_var_circuit(&mut self, bits: &[Var<C::N>]) -> Var<C::N> {
        let result: Var<_> = self.eval(C::N::zero());
        for i in 0..bits.len() {
            self.assign(result, result + bits[i] * C::N::from_canonical_u32(1 << i));
        }
        result
    }
}
