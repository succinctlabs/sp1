use hashbrown::HashMap;

use p3_field::AbstractField;

/// A record that can be proven by a machine.
pub trait MachineRecord: Default + Sized + Send + Sync + Clone {
    /// The configuration of the machine.
    type Config: 'static + Copy + Send + Sync;

    /// The statistics of the record.
    fn stats(&self) -> HashMap<String, usize>;

    /// Appends two records together.
    fn append(&mut self, other: &mut Self);

    /// Registers the nonces of the record.
    fn register_nonces(&mut self, _opts: &Self::Config) {}

    /// Returns the public values of the record.
    fn public_values<F: AbstractField>(&self) -> Vec<F>;
}
