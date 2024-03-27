#![no_main]
sp1_zkvm::entrypoint!(main);

extern "C" {
    fn syscall_blake3_compress_inner(p: *mut u32, q: *const u32);
}

pub fn main() {
    // The input message and state are simply 0, 1, ..., 95 followed by some fixed constants.
    for _i in 0..10 {
        let input_message: [u8; 64] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        ];

        let mut input_state: [u8; 64] = [
            64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85,
            86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 103, 230, 9, 106, 133, 174, 103, 187, 114, 243,
            110, 60, 58, 245, 79, 165, 96, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 97, 0, 0, 0,
        ];

        unsafe {
            syscall_blake3_compress_inner(
                input_state.as_mut_ptr() as *mut u32,
                input_message.as_ptr() as *const u32,
            );
        }

        // The expected output state is the result of compress_inner.
        let output_state: [u8; 64] = [
            239, 181, 94, 129, 58, 124, 80, 104, 126, 210, 5, 157, 255, 58, 238, 89, 252, 106, 170,
            12, 233, 56, 58, 31, 215, 16, 105, 97, 11, 229, 238, 73, 6, 79, 155, 180, 197, 73, 116,
            0, 127, 22, 16, 39, 116, 174, 85, 5, 61, 94, 87, 6, 236, 10, 36, 238, 119, 171, 207,
            171, 189, 216, 43, 250,
        ];

        assert_eq!(input_state, output_state);
    }

    println!("done");
}
