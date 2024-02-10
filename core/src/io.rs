use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::utils::{BabyBearBlake3, Buffer};
use crate::Proof;

#[derive(Serialize, Deserialize)]
pub struct SuccinctStdin {
    pub buffer: Buffer,
}

#[derive(Serialize, Deserialize)]
pub struct SuccinctStdout {
    pub buffer: Buffer,
}

impl SuccinctStdin {
    pub fn new() -> Self {
        Self {
            buffer: Buffer::new(),
        }
    }

    pub fn from(data: &[u8]) -> Self {
        Self {
            buffer: Buffer::from(data),
        }
    }

    pub fn read<T: Serialize + DeserializeOwned>(&mut self) -> T {
        self.buffer.read()
    }

    pub fn write<T: Serialize + DeserializeOwned>(&mut self, data: &T) {
        self.buffer.write(data);
    }
}

impl SuccinctStdout {
    pub fn new() -> Self {
        Self {
            buffer: Buffer::new(),
        }
    }

    pub fn from(data: &[u8]) -> Self {
        Self {
            buffer: Buffer::from(data),
        }
    }

    pub fn read<T: Serialize + DeserializeOwned>(&mut self) -> T {
        self.buffer.read()
    }

    pub fn write<T: Serialize + DeserializeOwned>(&mut self, data: &T) {
        self.buffer.write(data);
    }
}

pub fn serialize_proof<S>(proof: &Proof<BabyBearBlake3>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let bytes = bincode::serialize(proof).unwrap();
    let hex_bytes = hex::encode(bytes);
    serializer.serialize_str(&hex_bytes)
}
