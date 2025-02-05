/// The maximum size of the memory in bytes.
pub const MAXIMUM_MEMORY_SIZE: u32 = u32::MAX;

/// The number of bits in a byte.
pub const BYTE_SIZE: usize = 8;

/// The size of a word in bytes.
pub const WORD_SIZE: usize = 4;

/// The number of bytes necessary to represent a 64-bit integer.
pub const LONG_WORD_SIZE: usize = 2 * WORD_SIZE;

/// The Baby Bear prime.
pub const BABYBEAR_PRIME: u32 = 0x78000001;

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
pub fn words_to_bytes_le_vec(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes().into_iter()).collect::<Vec<_>>()
}

/// Converts a slice of words to a slice of bytes in little endian.
pub fn words_to_bytes_le<const B: usize>(words: &[u32]) -> [u8; B] {
    debug_assert_eq!(words.len() * 4, B);
    let mut iter = words.iter().flat_map(|word| word.to_le_bytes().into_iter());
    core::array::from_fn(|_| iter.next().unwrap())
}

/// Converts a byte array in little endian to a slice of words.
pub fn bytes_to_words_le<const W: usize>(bytes: &[u8]) -> [u32; W] {
    debug_assert_eq!(bytes.len(), W * 4);
    let mut iter = bytes.chunks_exact(4).map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()));
    core::array::from_fn(|_| iter.next().unwrap())
}

/// Converts a byte array in little endian to a vector of words.
pub fn bytes_to_words_le_vec(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
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
