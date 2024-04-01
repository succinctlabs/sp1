use std::collections::HashMap;

use crate::air::PublicValuesDigest;

pub trait MachineRecord: Default + Sized + Send + Sync {
    type Config: Default;

    fn index(&self) -> u32;

    fn set_index(&mut self, index: u32);

    fn stats(&self) -> HashMap<String, usize>;

    fn append(&mut self, other: &mut Self);

    fn shard(self, config: &Self::Config) -> Vec<Self>;

    fn public_values_digest(&self) -> Option<PublicValuesDigest<u32>>;

    fn set_public_values_digest(&mut self, digest: PublicValuesDigest<u32>);
}
