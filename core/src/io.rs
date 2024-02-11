use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::stark::StarkGenericConfig;
use crate::utils::Buffer;
use crate::Proof;

/// Standard input for the prover.
#[derive(Serialize, Deserialize)]
pub struct CurtaStdin {
    pub buffer: Buffer,
}

/// Standard output for the prover.
#[derive(Serialize, Deserialize)]
pub struct CurtaStdout {
    pub buffer: Buffer,
}

impl CurtaStdin {
    /// Create a new `CurtaStdin`.
    pub fn new() -> Self {
        Self {
            buffer: Buffer::new(),
        }
    }

    /// Create a `CurtaStdin` from a slice of bytes.
    pub fn from(data: &[u8]) -> Self {
        Self {
            buffer: Buffer::from(data),
        }
    }

    /// Read a value from the buffer.
    pub fn read<T: Serialize + DeserializeOwned>(&mut self) -> T {
        self.buffer.read()
    }

    /// Write a value to the buffer.
    pub fn write<T: Serialize + DeserializeOwned>(&mut self, data: &T) {
        self.buffer.write(data);
    }
}

impl CurtaStdout {
    /// Create a new `CurtaStdout`.
    pub fn new() -> Self {
        Self {
            buffer: Buffer::new(),
        }
    }

    /// Create a `CurtaStdout` from a slice of bytes.
    pub fn from(data: &[u8]) -> Self {
        Self {
            buffer: Buffer::from(data),
        }
    }

    /// Read a value from the buffer.    
    pub fn read<T: Serialize + DeserializeOwned>(&mut self) -> T {
        self.buffer.read()
    }

    /// Write a value to the buffer.
    pub fn write<T: Serialize + DeserializeOwned>(&mut self, data: &T) {
        self.buffer.write(data);
    }
}

pub fn serialize_proof<S, SC: StarkGenericConfig + Serialize>(
    proof: &Proof<SC>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let bytes = bincode::serialize(proof).unwrap();
    let hex_bytes = hex::encode(bytes);
    serializer.serialize_str(&hex_bytes)
}
