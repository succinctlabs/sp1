use std::ops::{Add, Mul};

use p3_field::AbstractField;
use sp1_core::stark::AirOpenedValues;

use crate::prelude::{Builder, Config, Ext, ExtConst, Felt, SymbolicExt, Usize, Var, Variable};

impl<C: Config> Builder<C> {
    pub fn const_opened_values(
        &mut self,
        opened_values: &AirOpenedValues<C::EF>,
    ) -> AirOpenedValues<Ext<C::F, C::EF>> {
        AirOpenedValues::<Ext<C::F, C::EF>> {
            local: opened_values
                .local
                .iter()
                .map(|s| self.eval(SymbolicExt::Const(*s)))
                .collect(),
            next: opened_values
                .next
                .iter()
                .map(|s| self.eval(SymbolicExt::Const(*s)))
                .collect(),
        }
    }

    pub fn exp_power_of_2_v<V: Variable<C>>(
        &mut self,
        base: impl Into<V::Expression>,
        power_log: Usize<C::N>,
    ) -> V
    where
        V: Copy + Mul<Output = V::Expression>,
    {
        let result: V = self.eval(base);
        self.range(0, power_log)
            .for_each(|_, builder| builder.assign(result, result * result));
        result
    }

    /// Multiplies `base` by `2^{log_power}`.
    pub fn sll<V: Variable<C>>(&mut self, base: impl Into<V::Expression>, shift: Usize<C::N>) -> V
    where
        V: Copy + Add<Output = V::Expression>,
    {
        let result: V = self.eval(base);
        self.range(0, shift)
            .for_each(|_, builder| builder.assign(result, result + result));
        result
    }

    pub fn power_of_two_usize(&mut self, power: Usize<C::N>) -> Usize<C::N> {
        self.sll(Usize::Const(1), power)
    }

    pub fn power_of_two_var(&mut self, power: Usize<C::N>) -> Var<C::N> {
        self.sll(C::N::one(), power)
    }

    pub fn power_of_two_felt(&mut self, power: Usize<C::N>) -> Felt<C::F> {
        self.sll(C::F::one(), power)
    }

    pub fn power_of_two_expr(&mut self, power: Usize<C::N>) -> Ext<C::F, C::EF> {
        self.sll(C::EF::one().cons(), power)
    }
}
