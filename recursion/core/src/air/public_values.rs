use crate::runtime::DIGEST_SIZE;

use arrayref::array_ref;
use core::fmt::Debug;
use p3_field::AbstractField;
use serde::{Deserialize, Serialize};

pub const PV_DIGEST_NUM_WORDS: usize = 8;

/// The PublicValues struct is used to store all of a shard proof's public values.
#[derive(Serialize, Deserialize, Clone, Copy, Default, Debug)]
pub struct PublicValues<T> {
    /// The hash of all the bytes that the program has written to public values.
    pub committed_value_digest: [T; DIGEST_SIZE],
}

impl<F: AbstractField> PublicValues<F> {
    /// Convert a vector of field elements into a PublicValues struct.
    pub fn from_vec(data: Vec<F>) -> Self {
        if data.len() < DIGEST_SIZE {
            panic!("Invalid number of items in the serialized vector.");
        }

        Self {
            committed_value_digest: array_ref![data, 0, DIGEST_SIZE].clone(),
        }
    }
}
