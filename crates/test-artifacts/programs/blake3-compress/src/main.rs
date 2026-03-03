#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::syscalls::syscall_blake3_compress_inner;

pub fn main() {
    // Blake3 IV (initialization vector) — first 8 words of the initial state.
    const IV: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ];

    // Test state: IV followed by counter/flags (simplified).
    // Each u32 Blake3 word is stored in a u64 slot (upper 32 bits zero).
    let mut state: [u64; 16] = [
        IV[0] as u64, IV[1] as u64, IV[2] as u64, IV[3] as u64,
        IV[4] as u64, IV[5] as u64, IV[6] as u64, IV[7] as u64,
        IV[0] as u64, IV[1] as u64, IV[2] as u64, IV[3] as u64,
        0, 0, 64, 11,
    ];
    let msg: [u64; 16] = [
        0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
        0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f,
        0x20212223, 0x24252627, 0x28292a2b, 0x2c2d2e2f,
        0x30313233, 0x34353637, 0x38393a3b, 0x3c3d3e3f,
    ];

    for _ in 0..4 {
        unsafe { syscall_blake3_compress_inner(state.as_mut_ptr(), msg.as_ptr()); }
    }

    sp1_zkvm::io::commit(&state);
}
