use std::ops::Mul;

use sp1_core::stark::AirOpenedValues;

use crate::prelude::{Builder, Config, Ext, SymbolicExt, Usize, Variable};

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
}
