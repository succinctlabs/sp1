#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let times = sp1_lib::io::read::<u8>();

    for _ in 0..times {
        let val: Vec<u8> = sp1_lib::io::read();
        let val = substrate_bn::Fq::from_slice(&val).unwrap();
        let sqrt = val.sqrt().unwrap();

        let mut sqrt_bytes = [0u8; 32];
        sqrt.to_big_endian(&mut sqrt_bytes).unwrap();
        sp1_lib::io::commit(&sqrt_bytes.to_vec());
    }
}
