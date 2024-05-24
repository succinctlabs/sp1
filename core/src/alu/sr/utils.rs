use super::BYTE_SIZE;

/// Calculate the number of bytes to shift by.
///
/// Note that we take the least significant 5 bits per the RISC-V spec.
pub const fn nb_bytes_to_shift(shift_amount: u32) -> usize {
    let n = (shift_amount % 32) as usize;
    n / BYTE_SIZE
}

/// Calculate the number of bits shift by.
///
/// Note that we take the least significant 5 bits per the RISC-V spec.
pub const fn nb_bits_to_shift(shift_amount: u32) -> usize {
    let n = (shift_amount % 32) as usize;
    n % BYTE_SIZE
}
