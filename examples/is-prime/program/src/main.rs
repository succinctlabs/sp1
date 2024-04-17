#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let n = sp1_zkvm::io::read::<u64>();

    let is_prime = is_prime(n);

    sp1_zkvm::io::commit(&is_prime);
}

// Returns if divisible via immediate checks than 6k ± 1.
// Source: https://en.wikipedia.org/wiki/Primality_test#Rust
fn is_prime(n: u64) -> bool {
    if n <= 1 {
        return false;
    }
    if n <= 3 {
        return true;
    }
    if n % 2 == 0 || n % 3 == 0 {
        return false;
    }
    let mut i = 5;
    while i * i <= n {
        if n % i == 0 || n % (i + 2) == 0 {
            return false;
        }
        i += 6;
    }
    true
}
