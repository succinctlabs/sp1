use std::io::Read;

use serde::{de::DeserializeOwned, Serialize};
use sp1_stark::{baby_bear_poseidon2::BabyBearPoseidon2, StarkVerifyingKey};

use super::Executor;
use crate::SP1ReduceProof;

impl<'a> Read for Executor<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read_public_values_slice(buf);
        Ok(buf.len())
    }
}

impl<'a> Executor<'a> {
    /// Write a serializable input to the standard input stream.
    pub fn write_stdin<T: Serialize>(&mut self, input: &T) {
        let mut buf = Vec::new();
        bincode::serialize_into(&mut buf, input).expect("serialization failed");
        self.state.input_stream.push(buf);
    }

    /// Write a slice of bytes to the standard input stream.
    pub fn write_stdin_slice(&mut self, input: &[u8]) {
        self.state.input_stream.push(input.to_vec());
    }

    /// Write a slice of vecs to the standard input stream.
    pub fn write_vecs(&mut self, inputs: &[Vec<u8>]) {
        for input in inputs {
            self.state.input_stream.push(input.clone());
        }
    }

    /// Write a proof and verifying key to the proof stream.
    pub fn write_proof(
        &mut self,
        proof: SP1ReduceProof<BabyBearPoseidon2>,
        vk: StarkVerifyingKey<BabyBearPoseidon2>,
    ) {
        self.state.proof_stream.push((proof, vk));
    }

    /// Read a serializable public values from the public values stream.
    pub fn read_public_values<T: DeserializeOwned>(&mut self) -> T {
        let result = bincode::deserialize_from::<_, T>(self);
        result.unwrap()
    }

    /// Read a slice of bytes from the public values stream.
    pub fn read_public_values_slice(&mut self, buf: &mut [u8]) {
        let len = buf.len();
        let start = self.state.public_values_stream_ptr;
        let end = start + len;
        assert!(end <= self.state.public_values_stream.len());
        buf.copy_from_slice(&self.state.public_values_stream[start..end]);
        self.state.public_values_stream_ptr = end;
    }
}
