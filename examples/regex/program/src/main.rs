//! A simple program that takes a regex pattern and a string and returns whether the string
//! matches the pattern.
#![no_main]
sp1_zkvm::entrypoint!(main);

use regex::Regex;

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.

pub fn main() {
    // Read two inputs from the prover: a regex pattern and a target string.
    let pattern = sp1_zkvm::io::read::<String>();
    let target_string = sp1_zkvm::io::read::<String>();

    // Try to compile the regex pattern. If it fails, write `false` as output and return.
    let regex = match Regex::new(&pattern) {
        Ok(regex) => regex,
        Err(_) => {
            panic!("Invalid regex pattern");
        }
    };

    // Perform the regex search on the target string.
    let result = regex.is_match(&target_string);

    // Write the result (true or false) to the output.
    sp1_zkvm::io::commit(&result);
}
