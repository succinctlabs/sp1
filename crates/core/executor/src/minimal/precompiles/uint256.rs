use num::{BigUint, One, Zero};

use sp1_curves::edwards::WORDS_FIELD_ELEMENT;
use sp1_jit::{Interrupt, SyscallContext};
use sp1_primitives::consts::{bytes_to_words_le, words_to_bytes_le_vec, WORD_BYTE_SIZE};

pub(crate) unsafe fn uint256_mul(
    ctx: &mut impl SyscallContext,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, Interrupt> {
    let x_ptr = arg1;
    if !x_ptr.is_multiple_of(8) {
        panic!();
    }
    let y_ptr = arg2;
    if !y_ptr.is_multiple_of(8) {
        panic!();
    }

    let clk = ctx.get_current_clk();
    ctx.read_slice_check(y_ptr, WORDS_FIELD_ELEMENT * 2)?;
    ctx.bump_memory_clk();
    ctx.read_write_slice_check(x_ptr, 4)?;

    ctx.set_clk(clk);
    // First read the words for the x value. We can read a slice_unsafe here because we write
    // the computed result to x later.
    let x = words_to_bytes_le_vec(ctx.mr_slice_unsafe(x_ptr, WORDS_FIELD_ELEMENT));

    // Read the y value.
    let y_and_modulus =
        words_to_bytes_le_vec(ctx.mr_slice_without_prot(y_ptr, WORDS_FIELD_ELEMENT * 2));

    let (y, modulus) = y_and_modulus.split_at(WORDS_FIELD_ELEMENT * WORD_BYTE_SIZE);

    // Get the BigUint values for x, y, and the modulus.
    let uint256_x = BigUint::from_bytes_le(&x);
    let uint256_y = BigUint::from_bytes_le(y);
    let uint256_modulus = BigUint::from_bytes_le(modulus);

    // Perform the multiplication and take the result modulo the modulus.
    let result: BigUint = if uint256_modulus.is_zero() {
        let modulus = BigUint::one() << 256;
        (uint256_x * uint256_y) % modulus
    } else {
        (uint256_x * uint256_y) % uint256_modulus
    };

    let mut result_bytes = result.to_bytes_le();
    result_bytes.resize(32, 0u8); // Pad the result to 32 bytes.

    // Convert the result to little endian u32 words.
    let result = bytes_to_words_le::<4>(&result_bytes);

    ctx.bump_memory_clk();

    // Write the result to x and keep track of the memory records.
    ctx.mw_slice_without_prot(x_ptr, &result);

    Ok(None)
}
