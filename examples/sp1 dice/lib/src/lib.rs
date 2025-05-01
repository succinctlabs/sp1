use alloy_sol_types::sol;

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        uint32 seed;
        uint32 dice_roll;
    }
}

/// Generate a dice roll (1-6) based on the provided seed
pub fn roll_dice(seed: u32) -> u32 {
    // Simple deterministic pseudo-random number algorithm
    // Using a simple hash-like function to increase entropy
    let x = seed.wrapping_mul(1664525).wrapping_add(1013904223);
    let result = ((x >> 16) % 6) + 1;
    result
}
