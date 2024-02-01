#![no_main]
extern crate succinct_zkvm;
succinct_zkvm::entrypoint!(main);

fn main() {
    let n = 20;
    let mut a = 0;
    let mut b = 2;
    for _ in 0..n {
        let temp = a;
        a = b;
        b += temp;
    }
    println!("b: {}", b);
}
