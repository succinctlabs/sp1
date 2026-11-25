#![no_main]
sp1_zkvm::entrypoint!(main);

#[path = "../xof_cases.rs"]
mod xof_cases;

pub fn main() {
    sp1_zkvm::io::commit(&xof_cases::turbo_shake_cases());
}
