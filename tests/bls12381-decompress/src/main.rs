#![no_main]
sp1_zkvm::entrypoint!(main);

extern "C" {
    fn syscall_bls12381_decompress(p: &mut [u8; 96], is_odd: bool);
}

pub fn main() {
    let compressed_key: [u8; 48] = sp1_zkvm::io::read_vec().try_into().unwrap();

    for _ in 0..4 {
        let mut decompressed_key: [u8; 96] = [0u8; 96];

        decompressed_key[..48].copy_from_slice(&compressed_key);

        println!("before: {:?}", decompressed_key);

        let is_odd = (decompressed_key[0] & 0b_0010_0000) >> 5 == 0;
        decompressed_key[0] &= 0b_0001_1111;

        unsafe {
            syscall_bls12381_decompress(&mut decompressed_key, is_odd);
        }

        println!("after: {:?}", decompressed_key);
        sp1_zkvm::io::commit_slice(&decompressed_key);
    }
}
