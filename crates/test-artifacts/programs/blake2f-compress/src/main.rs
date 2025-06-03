#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::syscalls::syscall_blake2f_compress;

pub fn main() {
    // Parse the hex string into bytes
    let hex_str = "0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000";
    let mut bytes = Vec::new();
    for i in 0..hex_str.len() / 2 {
        let byte = u8::from_str_radix(&hex_str[i*2..i*2+2], 16).unwrap();
        bytes.push(byte);
    }

    // Convert bytes to u32 array for state
    let mut state = [0u32; 213];
    for i in 0..bytes.len() / 4 {
        state[i] = u32::from_le_bytes([
            bytes[i*4],
            bytes[i*4+1],
            bytes[i*4+2],
            bytes[i*4+3],
        ]);
    }

    syscall_blake2f_compress(&mut state);

    // Expected output: 75ab69d3190a562c51aef8d88f1c2775876944407270c42c9844252c26d2875298743e7f6d5ea2f2d3e8d226039cd31b4e426ac4f2d3d666a610c2116fde4735
}
