use sp1_primitives::consts::WORD_SIZE;

use super::BYTE_SIZE;

pub const fn get_msb(a: [u8; WORD_SIZE]) -> u8 {
    (a[WORD_SIZE - 1] >> (BYTE_SIZE - 1)) & 1
}
