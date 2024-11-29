use sha2::{Digest, Sha256};

pub trait AsLittleEndianBytes {
    fn to_little_endian(self) -> Self;
}

impl<const N: usize> AsLittleEndianBytes for [u8; N] {
    fn to_little_endian(mut self) -> Self {
        self.reverse();
        self
    }
}

pub fn sha256_hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn hash_pairs(hash_1: [u8; 32], hash_2: [u8; 32]) -> [u8; 32] {
    // [0] & [1] Combine hashes into one 64 byte array, reversing byte order
    let combined_hashes: [u8; 64] = hash_1
        .into_iter()
        .rev()
        .chain(hash_2.into_iter().rev())
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();

    // [2] Double sha256 combined hashes
    let new_hash_be = sha256_hash(&sha256_hash(&combined_hashes));

    // [3] Convert new hash to little-endian
    new_hash_be.to_little_endian()
}

pub fn get_merkle_root(leaves: Vec<[u8; 32]>) -> [u8; 32] {
    let mut current_level = leaves;
    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;

        while i < current_level.len() {
            let left = current_level[i];
            let right = if i + 1 < current_level.len() {
                current_level[i + 1]
            } else {
                left
            };

            let parent_hash = hash_pairs(left, right);
            next_level.push(parent_hash);

            i += 2;
        }
        current_level = next_level;
    }
    current_level[0]
}
