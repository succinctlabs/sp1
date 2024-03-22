use crate::prelude::{Array, Builder, Config, MemVariable};

impl<C: Config> Builder<C> {
    pub fn clear<V: MemVariable<C>>(&mut self, array: Array<C, V>) {
        let empty = self.array::<V>(array.len());
        self.assign(array.clone(), empty);
    }
}
