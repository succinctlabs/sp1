#![no_main]

use sp1_zkvm::syscalls::{syscall_secp256k1_add, syscall_secp256k1_double};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    // The host supplies valid points P = 2G and Q = G, stored as aligned coordinate words.
    let (mode, iterations, mut p, mut q): (String, u32, [u64; 8], [u64; 8]) = sp1_zkvm::io::read();

    match mode.as_str() {
        "add" => {
            for _ in 0..iterations {
                syscall_secp256k1_add(&mut p, &mut q);
            }
        }
        "double" => {
            for _ in 0..iterations {
                syscall_secp256k1_double(&mut p);
            }
        }
        "mixed" => {
            for _ in 0..iterations {
                syscall_secp256k1_double(&mut p);
                syscall_secp256k1_double(&mut p);
                syscall_secp256k1_add(&mut p, &mut q);
            }
        }
        _ => panic!("unknown secp256k1 benchmark mode"),
    }

    // Return both points so the host can check the result and that Q was not modified.
    sp1_zkvm::io::commit(&(p, q));
}
