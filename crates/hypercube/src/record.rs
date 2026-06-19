use crate::{air::SP1AirBuilder, InteractionKind};
use hashbrown::HashMap;
use slop_algebra::AbstractField;
// Re-exported so downstream crates implementing `MachineRecord` can name the
// `global_challenge_input` bound without taking a direct `slop-challenger` dependency.
pub use slop_challenger::IopCtx;

/// A record that can be proven by a machine.
pub trait MachineRecord: Default + Sized + Send + Sync + Clone {
    /// The statistics of the record.
    fn stats(&self) -> HashMap<String, usize>;

    /// Appends two records together.
    fn append(&mut self, other: &mut Self);

    /// Returns the public values of the record.
    fn public_values<F: AbstractField>(&self) -> Vec<F>;

    // /// Extracts the global cumulative sum from the public values.
    // fn global_cumulative_sum<F: Field>(public_values: &[F]) -> SepticDigest<F>;

    /// Constrains the public values of the record.
    fn eval_public_values<AB: SP1AirBuilder>(builder: &mut AB);

    /// The interaction kinds that appear in `eval_public_values`. Needed so that the shard verifier
    /// knows how much randomness to allocate for the `LogUpGkr` `beta_seed` challenge.
    fn interactions_in_public_values() -> Vec<InteractionKind>;

    /// The chunk's ordered global-trace commitments.
    fn global_challenge_input<GC: IopCtx>(&self) -> Option<Vec<GC::Digest>> {
        None
    }
}

/// This exists only for the zerocheck unit test on `MinimalAddChip`.
impl MachineRecord for Vec<(u32, u32, u32)> {
    fn stats(&self) -> HashMap<String, usize> {
        let mut map = HashMap::new();
        map.insert("num_addi".to_string(), self.len());
        map
    }

    fn append(&mut self, other: &mut Self) {
        self.append(other);
    }

    fn public_values<F: AbstractField>(&self) -> Vec<F> {
        vec![]
    }

    fn eval_public_values<AB: SP1AirBuilder>(_builder: &mut AB) {}

    fn interactions_in_public_values() -> Vec<InteractionKind> {
        vec![]
    }
}
