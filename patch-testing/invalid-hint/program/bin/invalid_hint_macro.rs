//! Reads a `u8` flag from stdin. If non-zero, calls
//! `sp1_lib::invalid_hint!("...")` and the program halts with exit code 3
//! (after printing the message to stderr). Otherwise commits and exits 0.

#![no_main]
sp1_zkvm::entrypoint!(main);

fn main() {
    let trigger = sp1_lib::io::read::<u8>();
    if trigger != 0 {
        sp1_lib::invalid_hint!(
            "test halt: trigger byte was {} (non-zero), simulating a wrong-hint exit",
            trigger
        );
    }
    sp1_lib::io::commit::<u8>(&trigger);
}
