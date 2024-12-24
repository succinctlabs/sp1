#![no_main]
sp1_zkvm::entrypoint!(main);

use crypto_bigint::{Limb, Uint};

pub fn main() {
    let a_words: [u32; 8] = [u32::MAX; 8];
    let b_words: [u32; 8] = [u32::MAX; 8];
    let c: u32 = 356u32;
    let a = Uint::<8>::from_words(a_words);
    let b = Uint::<8>::from_words(b_words);
    let c = Limb(c);
    let result = a.mul_mod_special(&b, c);
}
