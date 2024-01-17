#![no_main]

extern crate succinct_zkvm;

succinct_zkvm::entrypoint!(main);

pub fn main() {
    panic!("this is a panic!");
}
