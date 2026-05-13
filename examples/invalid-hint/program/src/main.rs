//! Demonstrates `sp1_lib::invalid_hint!` and exit code 3.
//!
//! Reads one byte from stdin: when it's non-zero, the program calls
//! `invalid_hint!`, writes a diagnostic to stderr, and halts with exit
//! code 3 (`StatusCode::INVALID_HINT`). When it's zero, the program
//! terminates normally.
//!
//! Patched crypto crates use the same primitive on hint-validation
//! failures so a malicious prover cannot forge a regular `panic!`
//! (exit code 1) by feeding wrong hint data.

#![no_main]
sp1_zkvm::entrypoint!(main);

fn main() {
    let trigger = sp1_lib::io::read::<u8>();

    if trigger != 0 {
        // Format args work just like `panic!` — the message gets written
        // to FD 2 (stderr) before the program halts.
        sp1_lib::invalid_hint!(
            "hint check failed: trigger byte was {} (non-zero)",
            trigger
        );
    }

    // Happy path: commit the trigger value back to the host.
    sp1_lib::io::commit::<u8>(&trigger);
}
