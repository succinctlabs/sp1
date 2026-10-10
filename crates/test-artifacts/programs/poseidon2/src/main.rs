#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::syscalls::{Poseidon2ByteHash, Poseidon2State};

/// Exercises the two hashing surfaces `sp1-lib` exposes over the Poseidon2 precompile, and commits
/// every digest so the host can compare them against the permutation the prover hashes with.
///
/// Nothing else checks that in-guest Poseidon2 agrees with host-side Poseidon2, which is the
/// property any program that hashes in the guest and verifies the digest outside it depends on.
pub fn main() {
    // The raw field-element sponge. `Poseidon2State` only exposes the rate, so this is the widest
    // view of the bare permutation a guest can actually drive.
    let field_blocks = sp1_zkvm::io::read::<Vec<[u32; 8]>>();
    let mut state = Poseidon2State::default();
    for block in &field_blocks {
        state.absorb_field_block_unchecked(block);
    }
    sp1_zkvm::io::commit(&state.output());

    // The length-prefixed byte hasher. The host supplies messages that straddle the 24-byte block
    // boundary and messages that differ only by trailing zeros.
    let messages = sp1_zkvm::io::read::<Vec<Vec<u8>>>();
    for message in &messages {
        sp1_zkvm::io::commit(&Poseidon2ByteHash::hash(message));
    }
}
