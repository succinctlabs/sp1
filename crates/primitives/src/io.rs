use crate::types::Buffer;
use num_bigint::BigUint;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Public values for the prover.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SP1PublicValues {
    buffer: Buffer,
}

impl SP1PublicValues {
    pub fn raw(&self) -> String {
        format!("0x{}", hex::encode(self.buffer.data.clone()))
    }

    /// Create a `SP1PublicValues` from a slice of bytes.
    pub fn from(data: &[u8]) -> Self {
        Self { buffer: Buffer::from(data) }
    }

    pub fn as_slice(&self) -> &[u8] {
        self.buffer.data.as_slice()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.buffer.data.clone()
    }

    /// Read a value from the buffer.
    pub fn read<T: Serialize + DeserializeOwned>(&mut self) -> T {
        self.buffer.read()
    }

    /// Read a slice of bytes from the buffer.
    pub fn read_slice(&mut self, slice: &mut [u8]) {
        self.buffer.read_slice(slice);
    }

    /// Write a value to the buffer.
    pub fn write<T: Serialize>(&mut self, data: &T) {
        self.buffer.write(data);
    }

    /// Write a slice of bytes to the buffer.
    pub fn write_slice(&mut self, slice: &[u8]) {
        self.buffer.write_slice(slice);
    }

    /// Hash the public values.
    pub fn hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.buffer.data.as_slice());
        hasher.finalize().to_vec()
    }

    /// Hash the public values, mask the top 3 bits and return a BigUint. Matches the implementation
    /// of `hashPublicValues` in the Solidity verifier.
    ///
    /// ```solidity
    /// sha256(publicValues) & bytes32(uint256((1 << 253) - 1));
    /// ```
    pub fn hash_bn254(&self) -> BigUint {
        // Hash the public values.
        let mut hasher = Sha256::new();
        hasher.update(self.buffer.data.as_slice());
        let hash_result = hasher.finalize();
        let mut hash = hash_result.to_vec();

        // Mask the top 3 bits.
        hash[0] &= 0b00011111;

        // Return the masked hash as a BigUint.
        BigUint::from_bytes_be(&hash)
    }
}

impl AsRef<[u8]> for SP1PublicValues {
    fn as_ref(&self) -> &[u8] {
        &self.buffer.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestStruct {
        a: u32,
        b: String,
    }

    #[test]
    fn test_new() {
        let public_values = SP1PublicValues::default();
        assert!(public_values.buffer.data.is_empty());
    }

    #[test]
    fn test_from_slice() {
        let data = b"test data";
        let public_values = SP1PublicValues::from(data.as_ref());
        assert_eq!(public_values.buffer.data, data);
    }

    #[test]
    fn test_raw() {
        let data = b"test raw data";
        let public_values = SP1PublicValues::from(data.as_ref());
        let expected_hex = format!("0x{}", hex::encode(data));
        assert_eq!(public_values.raw(), expected_hex);
    }

    #[test]
    fn test_as_slice() {
        let data = b"test slice data";
        let public_values = SP1PublicValues::from(data.as_ref());
        assert_eq!(public_values.as_slice(), data);
    }

    #[test]
    fn test_to_vec() {
        let data = b"test vec data";
        let public_values = SP1PublicValues::from(data.as_ref());
        assert_eq!(public_values.to_vec(), data.to_vec());
    }

    #[test]
    fn test_write_and_read() {
        let mut public_values = SP1PublicValues::default();
        let obj = TestStruct { a: 123, b: "test".to_string() };

        public_values.write(&obj);
        let read_obj: TestStruct = public_values.read();
        assert_eq!(read_obj, obj);
    }

    #[test]
    fn test_write_slice_and_read_slice() {
        let mut public_values = SP1PublicValues::default();
        let slice = [1, 2, 3, 4, 5];
        public_values.write_slice(&slice);

        let mut read_slice = [0; 5];
        public_values.read_slice(&mut read_slice);
        assert_eq!(read_slice, slice);
    }

    #[test]
    fn test_hash() {
        let data = b"some data to hash";
        let public_values = SP1PublicValues::from(data.as_ref());
        let expected_hash = Sha256::digest(data).to_vec();
        assert_eq!(public_values.hash(), expected_hash);
    }

    #[test]
    fn test_hash_public_values() {
        let test_hex = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let test_bytes = hex::decode(test_hex).unwrap();

        let mut public_values = SP1PublicValues::default();
        public_values.write_slice(&test_bytes);
        let hash = public_values.hash_bn254();

        let expected_hash = "1ce987d0a7fcc2636fe87e69295ba12b1cc46c256b369ae7401c51b805ee91bd";
        let expected_hash_biguint = BigUint::from_bytes_be(&hex::decode(expected_hash).unwrap());

        assert_eq!(hash, expected_hash_biguint);
    }
}
