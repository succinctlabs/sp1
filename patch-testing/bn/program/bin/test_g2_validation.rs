#![no_main]
sp1_zkvm::entrypoint!(main);

include!("../g2_validation.rs");

pub fn main() {
    let substrate: bool = sp1_zkvm::io::read();
    let coordinates: [[u8; 32]; 4] = sp1_zkvm::io::read();
    let scaled: bool = sp1_zkvm::io::read();
    macro_rules! convert {
        ($bn:ident) => {{
            let point = validation_point!($bn, coordinates, scaled);
            sp1_zkvm::io::commit(&1u8);
            let _ = $bn::AffineG2::from(point);
            sp1_zkvm::io::commit(&2u8);
        }};
    }
    if substrate {
        convert!(substrate_bn_substrate);
    } else {
        convert!(substrate_bn);
    }
}
