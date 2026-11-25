#![no_main]
sp1_zkvm::entrypoint!(main);

mod cases {
    use crypto_bigint as bigint;
    include!("../residue_cases.rs");
}

pub fn main() {
    let mode: u8 = sp1_zkvm::io::read();
    sp1_zkvm::io::commit(&cases::run(mode));
}
