#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    use bls12_381::fp::Fp;

    let times = sp1_lib::io::read::<u8>();

    for _ in 0..times {
        let val1: Vec<u8> = sp1_lib::io::read();
        let val2: Vec<u8> = sp1_lib::io::read();

        let val1 = Fp::from_bytes(&val1.try_into().expect("[u8; 48] for fp")).unwrap();
        let val2 = Fp::from_bytes(&val2.try_into().expect("[u8; 48] for fp")).unwrap();

        let product = val1 * val2;

        sp1_lib::io::commit(&product.to_bytes().to_vec());
    }
}