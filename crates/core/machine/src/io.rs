use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sp1_core_executor::SP1ReduceProof;
use sp1_stark::{baby_bear_poseidon2::BabyBearPoseidon2, StarkVerifyingKey};

/// Standard input for the prover.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SP1Stdin {
    /// Input stored as a vec of vec of bytes. It's stored this way because the read syscall reads
    /// a vec of bytes at a time.
    pub buffer: Vec<Vec<u8>>,
    pub ptr: usize,
    pub proofs: Vec<(SP1ReduceProof<BabyBearPoseidon2>, StarkVerifyingKey<BabyBearPoseidon2>)>,
}

impl SP1Stdin {
    /// Create a new `SP1Stdin`.
    pub const fn new() -> Self {
        Self { buffer: Vec::new(), ptr: 0, proofs: Vec::new() }
    }

    /// Create a `SP1Stdin` from a slice of bytes.
    pub fn from(data: &[u8]) -> Self {
        Self { buffer: vec![data.to_vec()], ptr: 0, proofs: Vec::new() }
    }

    /// Read a value from the buffer.
    pub fn read<T: DeserializeOwned>(&mut self) -> T {
        let result: T =
            bincode::deserialize(&self.buffer[self.ptr]).expect("failed to deserialize");
        self.ptr += 1;
        result
    }

    /// Read a slice of bytes from the buffer.
    pub fn read_slice(&mut self, slice: &mut [u8]) {
        slice.copy_from_slice(&self.buffer[self.ptr]);
        self.ptr += 1;
    }

    /// Write a value to the buffer.
    pub fn write<T: Serialize>(&mut self, data: &T) {
        let mut tmp = Vec::new();
        bincode::serialize_into(&mut tmp, data).expect("serialization failed");
        self.buffer.push(tmp);
    }

    /// Write a slice of bytes to the buffer.
    pub fn write_slice(&mut self, slice: &[u8]) {
        self.buffer.push(slice.to_vec());
    }

    pub fn write_vec(&mut self, vec: Vec<u8>) {
        self.buffer.push(vec);
    }

    pub fn write_proof(
        &mut self,
        proof: SP1ReduceProof<BabyBearPoseidon2>,
        vk: StarkVerifyingKey<BabyBearPoseidon2>,
    ) {
        self.proofs.push((proof, vk));
    }
}

pub mod proof_serde {
    use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize};
    use sp1_stark::{MachineProof, StarkGenericConfig};

    pub fn serialize<S, SC: StarkGenericConfig + Serialize>(
        proof: &MachineProof<SC>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            let bytes = bincode::serialize(proof).unwrap();
            let hex_bytes = hex::encode(bytes);
            serializer.serialize_str(&hex_bytes)
        } else {
            proof.serialize(serializer)
        }
    }

    pub fn deserialize<'de, D, SC: StarkGenericConfig + DeserializeOwned>(
        deserializer: D,
    ) -> Result<MachineProof<SC>, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let hex_bytes = String::deserialize(deserializer).unwrap();
            let bytes = hex::decode(hex_bytes).unwrap();
            let proof = bincode::deserialize(&bytes).map_err(serde::de::Error::custom)?;
            Ok(proof)
        } else {
            MachineProof::<SC>::deserialize(deserializer)
        }
    }
}
