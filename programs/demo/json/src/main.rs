#![no_main]
curta_zkvm::entrypoint!(main);

use serde_json::Value;

fn main() {
    let data_str = curta_zkvm::io::read::<String>();
    let key = curta_zkvm::io::read::<String>();
    let v: Value = serde_json::from_str(&data_str).unwrap();
    let val = &v[key];
    curta_zkvm::io::write(&val);
}
