#![no_main]
sp1_zkvm::entrypoint!(main);
use crypto_bigint::{Encoding, Limb, U128, U256, U512, U64};

pub fn main() {
    let count: u32 = sp1_zkvm::io::read();
    for _ in 0..count {
        let a = sp1_zkvm::io::read_vec();
        let b = sp1_zkvm::io::read_vec();
        let c: u64 = sp1_zkvm::io::read();
        macro_rules! multiply {
            ($uint:ty) => {{
                let result = <$uint>::from_be_slice(&a)
                    .mul_mod_special(&<$uint>::from_be_slice(&b), Limb(c));
                sp1_zkvm::io::commit(&result.to_be_bytes().to_vec());
            }};
        }
        match a.len() {
            8 => multiply!(U64),
            16 => multiply!(U128),
            32 => multiply!(U256),
            64 => multiply!(U512),
            _ => panic!("unsupported test width"),
        }
    }
}
