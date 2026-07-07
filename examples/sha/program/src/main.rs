#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::syscalls::{syscall_sha256_compress, syscall_sha256_extend};

pub fn main() {
    let mut w = [1u64; 64];
    let mut state = [1u64; 8];

    for _ in 0..4 {
        syscall_sha256_compress(&mut w, &mut state);
    }

    println!("{:?}", state);

    let mut w = [1u64; 64];
    syscall_sha256_extend(&mut w);
    syscall_sha256_extend(&mut w);
    syscall_sha256_extend(&mut w);
    println!("{:?}", w);

    for _ in 0..4 {
        let mut random_w = [0u32; 64];
        random_w.fill_with(|| rand::random::<u32>());

        let mut random_w_u64 = [0u64; 64];
        for i in 0..64 {
            random_w_u64[i] = random_w[i] as u64;
        }

        let mut random_state = [0u32; 8];
        random_state.fill_with(|| rand::random::<u32>());

        let mut random_state_u64 = [0u64; 8];
        for i in 0..8 {
            random_state_u64[i] = random_state[i] as u64;
        }
        syscall_sha256_extend(&mut random_w_u64);
        syscall_sha256_compress(&mut random_w_u64, &mut random_state_u64);
    }
}
