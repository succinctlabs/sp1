#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let times = sp1_lib::io::read::<u8>();

    for _ in 0..times {
        let val: Vec<u8> = sp1_lib::io::read();
        let val = substrate_bn::Fr::from_slice(&val).unwrap();
        let inverse = val.inverse().unwrap();

        let mut inverse_bytes = [0u8; 32];
        inverse.to_big_endian(&mut inverse_bytes).unwrap();
        sp1_lib::io::commit(&inverse_bytes.to_vec());
    }
}
