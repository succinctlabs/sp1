use std::ops::MulAssign;

use super::{Builder, Config, Variable};

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
}
