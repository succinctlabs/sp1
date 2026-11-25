#![no_main]
sp1_zkvm::entrypoint!(main);

use base64::{engine::general_purpose, Engine as _};

pub fn main() {
    let encoded_string: String = sp1_zkvm::io::read();

    let decoded_bytes =
        general_purpose::STANDARD.decode(&encoded_string).expect("Failed to decode base64");

    sp1_zkvm::io::commit(&decoded_bytes);
}
