use elf::abi::{PF_NONE, PF_R, PF_W, PF_X};

/// The maximum size of the memory in bytes.
pub const MAXIMUM_MEMORY_SIZE: u64 = (1u64 << 48) - 1;

/// The maximum log2 size of native executor's memory
pub const MAX_JIT_LOG_ADDR: usize = 40;

/// The number of bits in a byte.
pub const BYTE_SIZE: usize = 8;

/// The number of bits in a limb.
pub const LIMB_SIZE: usize = 16;

/// The size of a word in limbs.
pub const WORD_SIZE: usize = 4;

/// The size of a word in bytes.
pub const WORD_BYTE_SIZE: usize = 2 * WORD_SIZE;

/// The size of an instruction in bytes.
pub const INSTRUCTION_WORD_SIZE: usize = 4;

/// The number of bytes necessary to represent a 128-bit integer.
pub const LONG_WORD_BYTE_SIZE: usize = 2 * WORD_BYTE_SIZE;

/// The log2 page size (in bytes).
pub const LOG_PAGE_SIZE: usize = 12;

/// The size of a page in bytes.
pub const PAGE_SIZE: usize = 1 << LOG_PAGE_SIZE;

/// MProtect flags.
pub const PROT_NONE: u8 = PF_NONE as u8;
pub const PROT_READ: u8 = PF_R as u8;
pub const PROT_WRITE: u8 = PF_W as u8;
pub const PROT_EXEC: u8 = PF_X as u8;
pub const DEFAULT_PAGE_PROT: u8 = PROT_READ | PROT_WRITE;

/// The type for the ELF note for enabling untrusted programs.
pub const NOTE_UNTRUSTED_PROGRAM_ENABLED: u32 = 1;

/// The stack top for the 64-bit zkvm.
pub const STACK_TOP: u64 = 0x78000000;

pub mod fd {
    /// The minimum file descriptor.
    ///
    /// Any file descriptor must be greater than this value, otherwise the executor will panic.
    ///
    /// This is useful for deprecating file descriptors.
    pub const LOWEST_ALLOWED_FD: u32 = 10;

    /// Creates a file descriptor constant, with respect to the minimum file descriptor.
    macro_rules! create_fd {
        ($(
            #[$attr:meta]
            pub const $name:ident: u32 = $value:expr;
        )*) => {
            $(
                #[$attr]
                pub const $name: u32 = $value + $crate::consts::fd::LOWEST_ALLOWED_FD;
            )*
        }
    }

    create_fd! {
        /// The file descriptor for public values.
        pub const FD_PUBLIC_VALUES: u32 = 3;

        /// The file descriptor for hints.
        pub const FD_HINT: u32 = 4;

        /// The file descriptor through which to access `hook_ecrecover`.
        pub const FD_ECRECOVER_HOOK: u32 = 5;

        /// The file descriptor through which to access `hook_ed_decompress`.
        pub const FD_EDDECOMPRESS: u32 = 6;

        /// The file descriptor through which to access `hook_rsa_mul_mod`.
        pub const FD_RSA_MUL_MOD: u32 = 7;

        /// The file descriptor through which to access `hook_bls12_381_sqrt`.
        pub const FD_BLS12_381_SQRT: u32 = 8;

        /// The file descriptor through which to access `hook_bls12_381_inverse`.
        pub const FD_BLS12_381_INVERSE: u32 = 9;

        /// The file descriptor through which to access `hook_fp_sqrt`.
        pub const FD_FP_SQRT: u32 = 10;

        /// The file descriptor through which to access `hook_fp_inverse`.
        pub const FD_FP_INV: u32 = 11;
    }
}

/// Converts a slice of words to a byte vector in little endian.
pub fn words_to_bytes_le_vec<'a>(words: impl IntoIterator<Item = &'a u64>) -> Vec<u8> {
    words.into_iter().flat_map(|word| word.to_le_bytes().into_iter()).collect::<Vec<_>>()
}

/// Converts a slice of words to a slice of bytes in little endian.
pub fn words_to_bytes_le<'a, const B: usize>(words: impl IntoIterator<Item = &'a u64>) -> [u8; B] {
    let mut iter = words.into_iter().flat_map(|word| word.to_le_bytes().into_iter());
    core::array::from_fn(|_| iter.next().unwrap())
}

/// Converts a byte array in little endian to a slice of words.
pub fn bytes_to_words_le<const W: usize>(bytes: &[u8]) -> [u64; W] {
    debug_assert_eq!(bytes.len(), W * 8);
    let mut iter = bytes.chunks_exact(8).map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()));
    core::array::from_fn(|_| iter.next().unwrap())
}

/// Converts a byte array in little endian to a vector of words.
pub fn bytes_to_words_le_vec(bytes: &[u8]) -> Vec<u64> {
    bytes
        .chunks_exact(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<_>>()
}

// Converts a num to a string with commas every 3 digits.
pub fn num_to_comma_separated<T: ToString>(value: T) -> String {
    value
        .to_string()
        .chars()
        .rev()
        .collect::<Vec<_>>()
        .chunks(3)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(",")
        .chars()
        .rev()
        .collect()
}

/// Converts a little endian u32 array into u64 array.
pub fn u32_to_u64(limbs: &[u32]) -> Vec<u64> {
    debug_assert!(limbs.len().is_multiple_of(2), "need an even number of u32s");
    limbs.chunks_exact(2).map(|pair| (pair[0] as u64) | ((pair[1] as u64) << 32)).collect()
}

/// Converts a little endian u64 array into u32 array.
pub fn u64_to_u32<'a>(limbs: impl IntoIterator<Item = &'a u64>) -> Vec<u32> {
    limbs
        .into_iter()
        .flat_map(|x| {
            let lo = *x as u32;
            let hi = (*x >> 32) as u32;
            [lo, hi]
        })
        .collect()
}

/// Converts a 32-bit integer to a pair of 16-bit integers.
pub fn u32_to_u16_limbs(value: u32) -> [u16; 2] {
    [(value & 0xFFFF) as u16, (value >> 16) as u16]
}

/// Converts a 64-bit integer to four 16-bit integers.
pub fn u64_to_u16_limbs(value: u64) -> [u16; 4] {
    [(value & 0xFFFF) as u16, (value >> 16) as u16, (value >> 32) as u16, (value >> 48) as u16]
}

// Utility function to split a 64 bit page index into 3 limbs sized 4 bit, 16 bit, and 16 bit (least
// significant first).
pub fn split_page_idx(page_idx: u64) -> [u16; 3] {
    [(page_idx & 0xF) as u16, ((page_idx >> 4) & 0xFFFF) as u16, ((page_idx >> 20) & 0xFFFF) as u16]
}
