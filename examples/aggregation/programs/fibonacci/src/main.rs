//! A simple fibonacci program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let n = sp1_zkvm::io::read::<u32>();
    let mut a: u128 = 0;
    let mut b: u128 = 1;
    let mut sum: u128;

    for _ in 1..n {
        sum = a + b;
        a = b;
        b = sum;
    }

    sp1_zkvm::io::commit(&n);
    sp1_zkvm::io::commit(&b);
}
