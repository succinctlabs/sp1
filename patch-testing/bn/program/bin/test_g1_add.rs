#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let times = sp1_lib::io::read::<u8>();

    for _ in 0..times {
        let a_x: Vec<u8> = sp1_lib::io::read();
        let a_y: Vec<u8> = sp1_lib::io::read();
        let b_x: Vec<u8> = sp1_lib::io::read();
        let b_y: Vec<u8> = sp1_lib::io::read();
        let c_x: Vec<u8> = sp1_lib::io::read();
        let c_y: Vec<u8> = sp1_lib::io::read();

        let a_x = substrate_bn::Fq::from_slice(&a_x).unwrap();
        let a_y = substrate_bn::Fq::from_slice(&a_y).unwrap();
        let b_x = substrate_bn::Fq::from_slice(&b_x).unwrap();
        let b_y = substrate_bn::Fq::from_slice(&b_y).unwrap();
        let c_x = substrate_bn::Fq::from_slice(&c_x).unwrap();
        let c_y = substrate_bn::Fq::from_slice(&c_y).unwrap();

        let a = substrate_bn::AffineG1::new(a_x, a_y).unwrap();
        let b = substrate_bn::AffineG1::new(b_x, b_y).unwrap();
        let c = substrate_bn::AffineG1::new(c_x, c_y).unwrap();
        let c_pred = a + b;

        assert!(c == c_pred);
    }
}
