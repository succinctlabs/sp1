use crate::common::types::ChallengerType;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sp1_core::utils::baby_bear_poseidon2::Perm;
use std::{fs::File, io::Read};

pub fn read_bin_file_to_vec(mut file: File) -> Result<Vec<u8>> {
    let metadata = file.metadata()?;
    let file_size = metadata.len() as usize;
    let mut buffer = Vec::with_capacity(file_size);
    file.read_to_end(&mut buffer)?;

    Ok(buffer)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengerState {
    sponge_state: Vec<u8>,
    input_buffer: Vec<u8>,
    output_buffer: Vec<u8>,
}

impl ChallengerState {
    pub fn from(challenger: &ChallengerType) -> Self {
        Self {
            sponge_state: bincode::serialize(&challenger.sponge_state).unwrap(),
            input_buffer: bincode::serialize(&challenger.input_buffer).unwrap(),
            output_buffer: bincode::serialize(&challenger.output_buffer).unwrap(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        bincode::deserialize(bytes).unwrap()
    }

    pub fn to_challenger(&mut self, permutation: &Perm) -> ChallengerType {
        let mut challenger = ChallengerType::new(permutation.clone());
        challenger.sponge_state = bincode::deserialize(&self.sponge_state).unwrap();
        challenger.input_buffer = bincode::deserialize(&self.input_buffer).unwrap();
        challenger.output_buffer = bincode::deserialize(&self.output_buffer).unwrap();
        challenger
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }
}
