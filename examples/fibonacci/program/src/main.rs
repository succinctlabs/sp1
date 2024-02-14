#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let n = 50000;
    let mut a = 0;
    let mut b = 1;
    let mut sum;
    for _ in 1..n {
        sum = a + b;
        a = b;
        b = sum;
    }
    println!("b: {}", b);
    sp1_zkvm::io::write(&a);
    sp1_zkvm::io::write(&b);
}
