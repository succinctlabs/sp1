//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

/// Computes the (n-1)th and nth Fibonacci numbers modulo 7919.
pub fn main() {
    // Read the input.
    let n = sp1_zkvm::io::read::<u32>();

    // Validate input to prevent excessive computation.
    if n > 1000 {
        panic!("Input n is too large (max 1000)");
    }

    // Commit the input to public output.
    sp1_zkvm::io::commit(&n);

    // Compute the (n-1)th and nth Fibonacci numbers modulo 7919.
    let (a, b) = fibonacci(n);

    // Commit the outputs.
    sp1_zkvm::io::commit(&a);
    sp1_zkvm::io::commit(&b);
}

/// Computes the (n-1)th and nth Fibonacci numbers modulo 7919.
/// Returns (a, b) where a is the (n-1)th and b is the nth number.
fn fibonacci(n: u32) -> (u64, u64) {
    if n == 0 {
        return (0, 0); // (n-1)th is undefined, so return 0 for consistency.
    }
    if n == 1 {
        return (0, 1);
    }

    let mut a: u64 = 0;
    let mut b: u64 = 1;
    const MOD: u64 = 7919;

    for _ in 2..=n {
        // Use checked arithmetic to ensure safety.
        let c = a.checked_add(b).unwrap_or_else(|| panic!("Addition overflow"));
        a = b;
        b = c % MOD;
    }
    (a, b)
}
