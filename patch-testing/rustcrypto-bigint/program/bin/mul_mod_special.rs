#![no_main]
sp1_zkvm::entrypoint!(main);

use crypto_bigint::{Encoding, Limb, Uint};

pub fn main() {
    let times = sp1_lib::io::read::<u8>();

    for _ in 0..times {
        let a: [u32; 8] = sp1_lib::io::read::<Vec<u32>>().try_into().unwrap();
        let b: [u32; 8] = sp1_lib::io::read::<Vec<u32>>().try_into().unwrap();
        let a = Uint::<8>::from_words(a);
        let b = Uint::<8>::from_words(b);

        let c: u32 = 356u32;
        let c = Limb(c);
        let result = a.mul_mod_special(&b, c);

        sp1_lib::io::commit(&result.to_be_bytes().to_vec());
    }
}
