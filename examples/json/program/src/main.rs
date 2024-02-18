#![no_main]
sp1_zkvm::entrypoint!(main);

use serde_json::Value;

fn main() {
    let data_str = sp1_zkvm::io::read::<String>();
    let key = sp1_zkvm::io::read::<String>();
    let v: Value = serde_json::from_str(&data_str).unwrap();
    let val = &v[key];
    sp1_zkvm::io::write(&val);
}
