use super::{syscall_fp12_mulmod, syscall_fp_mulmod, syscall_uint256_mulmod};

pub const BIGINT_WIDTH_WORDS: usize = 8;
pub const FP_BIGINT_WIDTH_WORDS: usize = 12;

/// Sets result to be (x op y) % modulus. Currently only multiplication is supported. If modulus is
/// zero, the modulus applied is 2^256.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn sys_bigint(
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
        syscall_uint256_mulmod(result_ptr, concat_ptr);
    }
}

/// Sets result to be (x op y) % modulus. Currently only multiplication is supported. If modulus is
/// zero, the modulus applied is 2^384.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn sys_fp_bigint(
    result: *mut [u32; FP_BIGINT_WIDTH_WORDS],
    op: u32,
    x: *const [u32; FP_BIGINT_WIDTH_WORDS],
    y: *const [u32; FP_BIGINT_WIDTH_WORDS],
    modulus: *const [u32; FP_BIGINT_WIDTH_WORDS],
) {
    // Instantiate a new uninitialized array of words to place the concatenated y and modulus.
    let mut concat_y_modulus = core::mem::MaybeUninit::<[u32; FP_BIGINT_WIDTH_WORDS * 2]>::uninit();
    unsafe {
        let result_ptr = result as *mut u32;
        let x_ptr = x as *const u32;
        let y_ptr = y as *const u32;
        let concat_ptr = concat_y_modulus.as_mut_ptr() as *mut u32;

        // First copy the y value into the concatenated array.
        core::ptr::copy_nonoverlapping(y_ptr, concat_ptr, FP_BIGINT_WIDTH_WORDS);

        // Then, copy the modulus value into the concatenated array. Add the width of the y value
        // to the pointer to place the modulus value after the y value.
        core::ptr::copy_nonoverlapping(
            modulus as *const u32,
            concat_ptr.add(FP_BIGINT_WIDTH_WORDS),
            FP_BIGINT_WIDTH_WORDS,
        );

        // Copy x into the result array, as our syscall will write the result into the first input.
        core::ptr::copy_nonoverlapping(x as *const u32, result_ptr, FP_BIGINT_WIDTH_WORDS);

        // Call the fp_mul syscall to multiply the x value with the concatenated y and modulus.
        // This syscall writes the result in-place, so it will mutate the result ptr appropriately.
        syscall_fp_mulmod(result_ptr, concat_ptr);
    }
}

/// Sets result to be x * y with Fp12 arithmetic.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn sys_fp12_bigint(
    result: *mut [u32; 12 * FP_BIGINT_WIDTH_WORDS],
    x: *const [u32; 12 * FP_BIGINT_WIDTH_WORDS],
    y: *const [u32; 12 * FP_BIGINT_WIDTH_WORDS],
) {
    unsafe {
        let result_ptr = result as *mut u32;
        let x_ptr = x as *const u32;
        let y_ptr = y as *const u32;
        // Copy x into the result array, as our syscall will write the result into the first input.
        core::ptr::copy_nonoverlapping(x as *const u32, result_ptr, 12 * FP_BIGINT_WIDTH_WORDS);

        // Call the fp12_mul syscall to multiply the x value with the concatenated y and modulus.
        // This syscall writes the result in-place, so it will mutate the result ptr appropriately.
        syscall_fp12_mulmod(result_ptr, y_ptr);
    }
}
