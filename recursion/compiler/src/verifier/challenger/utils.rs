use p3_field::AbstractField;

use crate::prelude::{Array, Builder, Config, MemVariable};

impl<C: Config> Builder<C> {
    pub fn clear<V: MemVariable<C>>(&mut self, array: &mut Array<C, V>)
    where
        V::Expression: AbstractField,
    {
        self.range(0, array.len()).for_each(|i, builder| {
            builder.set(array, i, V::Expression::zero());
        });
    }
}
