#![no_main]
sp1_zkvm::entrypoint!(main);

include!("../affine_conversions.rs");

pub fn main() {
    let succinct = check_conversions!(substrate_bn);
    let substrate = check_conversions!(substrate_bn_substrate);
    assert_eq!(succinct, substrate);
    sp1_zkvm::io::commit(&succinct);
    sp1_zkvm::io::commit(&substrate);
}
