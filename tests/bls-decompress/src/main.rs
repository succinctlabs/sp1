#![no_main]
sp1_zkvm::entrypoint!(main);

extern "C" {
    fn syscall_bls12381_decompress(p: &mut [u8; 96]);
}

pub fn main() {
    let compressed_bytes = [
        177, 134, 13, 20, 73, 48, 251, 155, 49, 201, 87, 201, 41, 48, 254, 200, 184, 121, 200, 252,
        201, 226, 38, 41, 23, 1, 188, 146, 240, 80, 163, 56, 248, 24, 169, 52, 89, 122, 253, 98,
        13, 91, 145, 161, 120, 172, 56, 0,
    ];
    let mut decompressed: [u8; 96] = [0u8; 96];

    decompressed[..48].copy_from_slice(&compressed_bytes);

    println!("before: {:?}", decompressed);

    unsafe {
        syscall_bls12381_decompress(&mut decompressed);
    }

    let expected: [u8; 96] = [
        149, 44, 248, 74, 70, 106, 132, 143, 219, 246, 192, 254, 127, 165, 17, 133, 210, 70, 101,
        130, 115, 68, 231, 182, 71, 162, 197, 159, 3, 157, 68, 220, 97, 150, 107, 50, 80, 73, 227,
        244, 237, 62, 56, 11, 131, 118, 12, 23, 0, 56, 172, 120, 161, 145, 91, 13, 98, 253, 122,
        89, 52, 169, 24, 248, 56, 163, 80, 240, 146, 188, 1, 23, 41, 38, 226, 201, 252, 200, 121,
        184, 200, 254, 48, 41, 201, 87, 201, 49, 155, 251, 48, 73, 20, 13, 134, 17,
    ];

    assert_eq!(decompressed, expected);

    println!("after: {:?}", decompressed);
    println!("done");
}
