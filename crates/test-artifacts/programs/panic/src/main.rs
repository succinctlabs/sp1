#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    assert_eq!(0, 1);
}
