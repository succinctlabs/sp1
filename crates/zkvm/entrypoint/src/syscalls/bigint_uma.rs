use super::syscall_u256x2048_mul;

/// The number of limbs in a "uint256".
const N: usize = 8;

#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn sys_bigint_uma(
    result: *mut [u32; N],
    op: u32,
    x: *const [u32; N],
    y: *const [u32; N],
    modulus: *const [u32; N],
) {
    // Instantiate a new uninitialized array of words to place the concatenated y and modulus.
    let mut concat_y_modulus = core::mem::MaybeUninit::<[u32; N * 2]>::uninit();
    unsafe {
        let result_ptr = result as *mut u32;
        let x_ptr = x as *const u32;
        let y_ptr = y as *const u32;
        let concat_ptr = concat_y_modulus.as_mut_ptr() as *mut u32;

        // First copy the y value into the concatenated array.
        core::ptr::copy(y_ptr, concat_ptr, N);

        // Then, copy the modulus value into the concatenated array. Add the width of the y value
        // to the pointer to place the modulus value after the y value.
        core::ptr::copy(modulus as *const u32, concat_ptr.add(N), N);

        // Copy x into the result array, as our syscall will write the result into the first input.
        core::ptr::copy(x as *const u32, result_ptr, N);

        // Call the uint256_mul syscall to multiply the x value with the concatenated y and modulus.
        // This syscall writes the result in-place, so it will mutate the result ptr appropriately.
        let result_ptr = result_ptr as *mut [u32; N];
        let concat_ptr = concat_ptr as *mut [u32; N];
        syscall_u256x2048_mul(result_ptr, concat_ptr);
    }
}
