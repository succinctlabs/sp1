#![no_main]

use hex_literal::hex;

extern crate succinct_zkvm;

succinct_zkvm::entrypoint!(main);

extern "C" {
    fn syscall_ed_decompress(p: *mut u8);
}

pub fn main() {
    let pub_bytes = hex!("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");

    let mut decompressed = [0_u8; 64];
    decompressed[32..].copy_from_slice(&pub_bytes);

    println!("before: {:?}", decompressed);

    unsafe {
        syscall_ed_decompress(decompressed.as_mut_ptr());
    }

    println!("after: {:?}", decompressed);

    println!("done");
}
