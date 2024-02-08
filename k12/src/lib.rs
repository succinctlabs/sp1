//! The `KangarooTwelve` hash function.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use kangarootwelve_xkcp::Hasher;

use p3_symmetric::CryptographicHasher;

/// The `KangarooTwelve` hash functions defined in
/// [KangerooTwelve](https://eprint.iacr.org/2016/770.pdf).
#[derive(Copy, Clone)]
pub struct KangarooTwelve;

impl CryptographicHasher<u8, [u8; 32]> for KangarooTwelve {
    fn hash_iter<I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = u8>,
    {
        let input = input.into_iter().collect::<Vec<_>>();
        self.hash_iter_slices([input.as_slice()])
    }

    fn hash_iter_slices<'a, I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let mut hasher = Hasher::new();
        for chunk in input.into_iter() {
            hasher.update(chunk);
        }

        hasher.finalize().into()
    }
}
