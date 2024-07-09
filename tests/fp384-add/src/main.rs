#![no_main]
sp1_zkvm::entrypoint!(main);

use bytemuck;
use num::{BigUint, One};
use rand;
use rand::Rng;
const BIGINT_WIDTH_WORDS: usize = 12;

extern "C" {
    fn syscall_fp384_mul(x: *mut u32, y: *const u32);
}

/// Sets result to be (x op y) % modulus. Currently only multiplication is supported. If modulus is
/// zero, the modulus applied is 2^256.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn sys_biggerint(
    result: *mut [u32; BIGINT_WIDTH_WORDS],
    op: u32,
    x: *const [u32; BIGINT_WIDTH_WORDS],
    y: *const [u32; BIGINT_WIDTH_WORDS],
    modulus: *const [u32; BIGINT_WIDTH_WORDS],
) {
    // Instantiate a new uninitialized array of words to place the concatenated y and modulus.
    let mut concat_y_modulus = core::mem::MaybeUninit::<[u32; BIGINT_WIDTH_WORDS * 2]>::uninit();
    unsafe {
        let result_ptr = result as *mut u32;
        let x_ptr = x as *const u32;
        let y_ptr = y as *const u32;
        let concat_ptr = concat_y_modulus.as_mut_ptr() as *mut u32;

        // First copy the y value into the concatenated array.
        core::ptr::copy(y_ptr, concat_ptr, BIGINT_WIDTH_WORDS);

        // Then, copy the modulus value into the concatenated array. Add the width of the y value
        // to the pointer to place the modulus value after the y value.
        core::ptr::copy(
            modulus as *const u32,
            concat_ptr.add(BIGINT_WIDTH_WORDS),
            BIGINT_WIDTH_WORDS,
        );

        // Copy x into the result array, as our syscall will write the result into the first input.
        core::ptr::copy(x as *const u32, result_ptr, BIGINT_WIDTH_WORDS);

        // Call the uint256_mul syscall to multiply the x value with the concatenated y and modulus.
        // This syscall writes the result in-place, so it will mutate the result ptr appropriately.
        syscall_fp384_mul(result_ptr, concat_ptr);
    }
}

fn uint256_mul(x: &[u8; 48], y: &[u8; 48], modulus: &[u8; 48]) -> [u8; 48] {
    println!("cycle-tracker-start: uint256_mul");
    let mut result = [0u32; 12];
    sys_biggerint(
        result.as_mut_ptr() as *mut [u32; 12],
        0,
        x.as_ptr() as *const [u32; 12],
        y.as_ptr() as *const [u32; 12],
        modulus.as_ptr() as *const [u32; 12],
    );
    println!("cycle-tracker-end: uint256_mul");
    bytemuck::cast::<[u32; 12], [u8; 48]>(result)
}

fn biguint_to_bytes_le(x: BigUint) -> [u8; 48] {
    let mut bytes = x.to_bytes_le();
    bytes.resize(48, 0);
    bytes.try_into().unwrap()
}

fn main() {
    for _ in 0..50 {
        // Test with random numbers.
        let mut rng = rand::thread_rng();
        let mut x: [u8; 48] = (0..48)
            .map(|_| rng.gen::<u8>())
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();
        let mut y: [u8; 48] = (0..48)
            .map(|_| rng.gen::<u8>())
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();
        let mut modulus: [u8; 48] = (0..48)
            .map(|_| rng.gen::<u8>())
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();

        // Convert byte arrays to BigUint
        let modulus_big = BigUint::from_bytes_le(&modulus);
        let x_big = BigUint::from_bytes_le(&x);
        x = biguint_to_bytes_le(&x_big % &modulus_big);
        let y_big = BigUint::from_bytes_le(&y);
        y = biguint_to_bytes_le(&y_big % &modulus_big);

        let result_bytes = uint256_mul(&x, &y, &modulus);

        let result = (x_big * y_big) % modulus_big;
        let result_syscall = BigUint::from_bytes_le(&result_bytes);

        assert_eq!(result, result_syscall);
    }

    // Modulus zero tests
    let modulus = [0u8; 48];
    let modulus_big: BigUint = BigUint::one() << 256;
    for _ in 0..50 {
        // Test with random numbers.
        let mut rng = rand::thread_rng();
        let mut x: [u8; 48] = (0..48)
            .map(|_| rng.gen::<u8>())
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();
        let mut y: [u8; 48] = (0..48)
            .map(|_| rng.gen::<u8>())
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();

        // Convert byte arrays to BigUint
        let x_big = BigUint::from_bytes_le(&x);
        x = biguint_to_bytes_le(&x_big % &modulus_big);
        let y_big = BigUint::from_bytes_le(&y);
        y = biguint_to_bytes_le(&y_big % &modulus_big);

        let result_bytes = uint256_mul(&x, &y, &modulus);

        let result = (x_big * y_big) % &modulus_big;
        let result_syscall = BigUint::from_bytes_le(&result_bytes);

        assert_eq!(result, result_syscall, "x: {:?}, y: {:?}", x, y);
    }

    // Test with random numbers.
    let mut rng = rand::thread_rng();
    let x: [u8; 48] = (0..48)
        .map(|_| rng.gen::<u8>())
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();

    // Hardcoded edge case: Multiplying by 1
    let modulus = [0u8; 48];

    let mut one: [u8; 48] = [0; 48];
    one[0] = 1; // Least significant byte set to 1, represents the number 1
    let original_x = x; // Copy original x value before multiplication by 1
    let result_one = uint256_mul(&x, &one, &modulus);
    assert_eq!(
        result_one, original_x,
        "Multiplying by 1 should yield the same number."
    );

    // Hardcoded edge case: Multiplying by 0
    let zero: [u8; 48] = [0; 48]; // Represents the number 0
    let result_zero = uint256_mul(&x, &zero, &modulus);
    assert_eq!(result_zero, zero, "Multiplying by 0 should yield 0.");

    println!("All tests passed successfully!");
}
