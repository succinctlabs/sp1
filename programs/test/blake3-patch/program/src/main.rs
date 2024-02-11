//! A simple program to be proven inside the zkVM.

#![no_main]
curta_zkvm::entrypoint!(main);

use blake3;

pub fn main() {
    let n = curta_zkvm::io::read::<u32>();
    let mut a = 0;
    let mut b = 1;
    let mut sum;
    for _ in 1..n {
        sum = a + b;
        a = b;
        b = sum;
    }

    curta_zkvm::io::write(&a);
    curta_zkvm::io::write(&b);
}
