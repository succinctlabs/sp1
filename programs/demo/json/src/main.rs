//! Simple program to prove a key-value pair in a given JSON.
//!
use serde_json::Value;

// #![no_main]
curta_zkvm::entrypoint!(main);

pub fn main() {
    // get string
    let data_str = curta_zkvm::io::read::<String>();
    let key = curta_zkvm::io::read::<String>();

    let v: Value = serde_json::from_str(&data_str).unwrap();
    let val = &v[key];

    curta_zkvm::io::write(&val);
}
