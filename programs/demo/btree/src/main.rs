#![no_main]
curta_zkvm::entrypoint!(main);

use std::collections::BTreeMap;

pub fn main() {
    // Read tree and key-value pair
    let mut tree = curta_zkvm::io::read::<BTreeMap<String, String>>();
    let key = curta_zkvm::io::read::<String>();
    let value = curta_zkvm::io::read::<String>();

    // Insert value into tree
    tree.insert(key, value);

    // Write resulting tree to stdout
    curta_zkvm::io::write(&tree);
}
