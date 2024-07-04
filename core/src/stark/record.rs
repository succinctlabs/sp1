use hashbrown::HashMap;

use p3_field::AbstractField;

pub trait MachineRecord: Default + Sized + Send + Sync + Clone {
    type Config;

    fn stats(&self) -> HashMap<String, usize>;

    fn append(&mut self, other: &mut Self);

    #[allow(unused_variables)]
    fn register_nonces(&mut self, _syscall_lookups: &mut HashMap<u32, usize>, opts: &Self::Config) {
    }

    fn public_values<F: AbstractField>(&self) -> Vec<F>;
}
