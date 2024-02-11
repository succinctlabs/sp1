//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
curta_zkvm::entrypoint!(main);

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.
    let n = curta_zkvm::io::read::<u32>();

    // Compute the n'th fibonacci number, using normal Rust code.
    let mut a = 0;
    let mut b = 1;
    let mut sum;
    for _ in 1..n {
        sum = a + b;
        a = b;
        b = sum;
    }

    // Write the output of the program.
    //
    // Behind the scenes, this also compiles down to a custom system call which handles writing
    // outputs to the prover.
    curta_zkvm::io::write(&a);
    curta_zkvm::io::write(&b);
}
