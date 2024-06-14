#![no_main]
sp1_zkvm::entrypoint!(main);

use hex_literal::hex;

extern "C" {
    fn syscall_ed_decompress(p: *mut u8);
}

pub fn main() {
    for _ in 0..4 {
        let pub_bytes = hex!("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");

        let mut decompressed = [0_u8; 64];
        decompressed[32..].copy_from_slice(&pub_bytes);

        println!("before: {:?}", decompressed);

        unsafe {
            syscall_ed_decompress(decompressed.as_mut_ptr());
        }

        let expected: [u8; 64] = [
            47, 252, 114, 91, 153, 234, 110, 201, 201, 153, 152, 14, 68, 231, 90, 221, 137, 110,
            250, 67, 10, 64, 37, 70, 163, 101, 111, 223, 185, 1, 180, 88, 236, 23, 43, 147, 173,
            94, 86, 59, 244, 147, 44, 112, 225, 36, 80, 52, 195, 84, 103, 239, 46, 253, 77, 100,
            235, 248, 25, 104, 52, 103, 226, 63,
        ];

        assert_eq!(decompressed, expected);
        println!("after: {:?}", decompressed);
    }

    println!("done");
}
