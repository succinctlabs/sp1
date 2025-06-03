#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::syscalls::syscall_blake2f_compress;

pub fn main() {
    // Parse the hex string into bytes
    let input = "0000000048c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001";
    let expected = "08c9bcf367e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d282e6ad7f520e511f6c3e2b8c68059b9442be0454267ce079217e1319cde05b";
    let mut bytes = Vec::new();
    for i in 0..input.len() / 2 {
        let byte = u8::from_str_radix(&input[i*2..i*2+2], 16).unwrap();
        bytes.push(byte);
    }

    // Convert bytes to u32 array for state
    let mut state = [0u32; 54];
    for i in 0..bytes.len() / 4 {
        state[i] = u32::from_le_bytes([
            bytes[i*4],
            bytes[i*4+1],
            bytes[i*4+2],
            bytes[i*4+3],
        ]);
    }
    state[53] = u32::from_le_bytes([
        bytes[bytes.len() - 1], 0, 0, 0
    ]);

    syscall_blake2f_compress(&mut state);

    // Print the result
    println!("Expected Result: {}", expected);
}
