#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::syscalls::Poseidon2ByteHash;

pub fn main() {
    // Build ~10 MB of input data.
    let mut data = Vec::with_capacity(436906 * 4);
    for i in 0u32..436906 {
        data.extend_from_slice(&i.to_le_bytes());
    }

    let output = Poseidon2ByteHash::hash(&data);
    println!("poseidon2 hash: {:?}", output);
}
