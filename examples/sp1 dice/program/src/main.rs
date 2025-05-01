//! A program that takes a seed as input, and generates a provably fair dice roll (1-6).
// These two lines are necessary for the program to properly compile.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use dice_game_lib::{roll_dice, PublicValuesStruct};

pub fn main() {
    // Read the seed input to the program
    let seed = sp1_zkvm::io::read::<u32>();
    
    // Generate the dice roll using our function from the library
    let dice_roll = roll_dice(seed);
    
    // Encode the public values of the program
    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct { 
        seed, 
        dice_roll 
    });
    
    // Commit to the public values of the program
    sp1_zkvm::io::commit_slice(&bytes);
}
