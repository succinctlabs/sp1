#![no_main]

extern crate succinct_zkvm;

succinct_zkvm::entrypoint!(main);

extern "C" {
    fn syscall_poseidon2_external_1(p: *mut u32);
}

pub fn main() {
    // Input & output calculated in https://github.com/succinctlabs/vm/commit/682d58ec35129a98e553e3c3a6e48290a264bb10

    // Input.
    let mut a: [u8; 64] = [
        218, 1, 0, 0, 87, 1, 0, 0, 42, 2, 0, 0, 167, 1, 0, 0, 26, 2, 0, 0, 135, 1, 0, 0, 106, 2, 0,
        0, 215, 1, 0, 0, 90, 2, 0, 0, 183, 1, 0, 0, 170, 2, 0, 0, 7, 2, 0, 0, 154, 2, 0, 0, 231, 1,
        0, 0, 234, 2, 0, 0, 55, 2, 0, 0,
    ];

    unsafe {
        syscall_poseidon2_external_1(a.as_mut_ptr() as *mut u32);
    }

    // Expected output.
    let b: [u8; 64] = [
        233, 181, 226, 8, 91, 204, 88, 37, 225, 186, 240, 10, 152, 248, 47, 49, 80, 67, 217, 102,
        106, 34, 191, 20, 70, 123, 10, 36, 113, 92, 106, 82, 199, 128, 229, 45, 207, 155, 72, 5,
        59, 179, 239, 4, 68, 174, 157, 32, 143, 147, 24, 34, 174, 230, 241, 96, 14, 122, 134, 67,
        61, 183, 121, 39,
    ];

    assert_eq!(a, b);

    println!("done");
}
