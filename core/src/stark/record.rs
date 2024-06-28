use hashbrown::HashMap;

use p3_field::AbstractField;

pub trait MachineRecord: Default + Sized + Send + Sync + Clone {
    type Config: Default;

    fn index(&self) -> u32;

    fn set_index(&mut self, index: u32);

    fn stats(&self) -> HashMap<String, usize>;

    fn append(&mut self, other: &mut Self);

    fn register_nonces(&mut self) {}

    fn shard(self, config: &Self::Config) -> Vec<Self>;

    fn public_values<F: AbstractField>(&self) -> Vec<F>;
}
