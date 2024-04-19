//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a custom system call which handles reading inputs
    // from the prover.
    let n = sp1_zkvm::io::read::<u32>();

    // Write n to public input
    sp1_zkvm::io::commit(&n);

    // Compute the n'th fibonacci number, using normal Rust code.
    let mut nums = vec![1, 1];
    for _ in 0..n {
        let mut c = nums[nums.len() - 1] + nums[nums.len() - 2];
        c %= 7919;
        nums.push(c);
    }

    // Write the output of the program.
    //
    // Behind the scenes, this also compiles down to a custom system call which handles writing
    // outputs to the prover.
    sp1_zkvm::io::commit(&nums[nums.len() - 2]);
    sp1_zkvm::io::commit(&nums[nums.len() - 1]);
}
