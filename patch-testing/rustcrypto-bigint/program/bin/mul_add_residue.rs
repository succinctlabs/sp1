#![no_main]
sp1_zkvm::entrypoint!(main);

use crypto_bigint::modular::constant_mod::ResidueParams;
use crypto_bigint::{const_residue, impl_modulus, Encoding, U256};

pub fn main() {
    let times = sp1_lib::io::read::<u8>();

    impl_modulus!(
        Modulus,
        U256,
        "9CC24C5DF431A864188AB905AC751B727C9447A8E99E6366E1AD78A21E8D882B"
    );

    for _ in 0..times {
        let a: u64 = sp1_lib::io::read::<u64>();
        let b: u64 = sp1_lib::io::read::<u64>();
        let a = U256::from(a);
        let b = U256::from(b);
        let a_residue = const_residue!(a, Modulus);
        let b_residue = const_residue!(b, Modulus);

        let result = a_residue * b_residue + a_residue;

        sp1_lib::io::commit(&result.retrieve().to_be_bytes().to_vec());
    }
}
