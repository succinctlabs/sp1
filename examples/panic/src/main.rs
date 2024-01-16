#![no_main]

extern crate curta_zkvm;

curta_zkvm::entrypoint!(main);

pub fn main() {
    panic!("this is a panic!");
}
