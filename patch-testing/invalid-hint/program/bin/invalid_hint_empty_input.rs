//! Calls `read_vec` once. If the prover (test harness) didn't supply any
//! input, the read finds an empty stream and the patched `read_vec` halts
//! with exit code 3 (after writing the diagnostic message to stderr).

#![no_main]
sp1_zkvm::entrypoint!(main);

fn main() {
    let _ = sp1_lib::io::read_vec();
    // If we get here, input was supplied.
    sp1_lib::io::commit::<u8>(&0u8);
}
