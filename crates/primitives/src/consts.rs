/// The maximum size of the memory in bytes.
pub const MAXIMUM_MEMORY_SIZE: u32 = u32::MAX;

/// The size of a word in bytes.
pub const WORD_SIZE: usize = 4;

/// Converts a slice of words to a byte vector in little endian.
pub fn words_to_bytes_le_vec(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|&word| word.to_le_bytes()).collect()
}

/// Converts a slice of words to a slice of bytes in little endian.
pub fn words_to_bytes_le<const B: usize>(words: &[u32]) -> [u8; B] {
    debug_assert_eq!(words.len() * 4, B);
    let mut bytes = [0u8; B];
    words.iter().enumerate().for_each(|(i, &word)| {
        bytes[i * WORD_SIZE..(i + 1) * WORD_SIZE].copy_from_slice(&word.to_le_bytes());
    });
    bytes
}

/// Converts a byte array in little endian to a slice of words.
pub fn bytes_to_words_le<const W: usize>(bytes: &[u8]) -> [u32; W] {
    debug_assert_eq!(bytes.len(), W * 4);
    let mut words = [0u32; W];
    bytes.chunks_exact(WORD_SIZE).enumerate().for_each(|(i, chunk)| {
        words[i] = u32::from_le_bytes(chunk.try_into().unwrap());
    });
    words
}

/// Converts a byte array in little endian to a vector of words.
pub fn bytes_to_words_le_vec(bytes: &[u8]) -> Vec<u32> {
    bytes.chunks_exact(4).map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap())).collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_words_to_bytes_le_vec() {
        let words = [0x12345678, 0x90ABCDEF];
        let expected = vec![0x78, 0x56, 0x34, 0x12, 0xEF, 0xCD, 0xAB, 0x90];
        assert_eq!(words_to_bytes_le_vec(&words), expected);
    }

    #[test]
    fn test_words_to_bytes_le() {
        let words = [0x12345678, 0x90ABCDEF];
        let expected: [u8; 8] = [0x78, 0x56, 0x34, 0x12, 0xEF, 0xCD, 0xAB, 0x90];
        assert_eq!(words_to_bytes_le::<8>(&words), expected);
    }

    #[test]
    fn test_bytes_to_words_le() {
        let bytes = [0x78, 0x56, 0x34, 0x12, 0xEF, 0xCD, 0xAB, 0x90];
        let expected = [0x12345678, 0x90ABCDEF];
        assert_eq!(bytes_to_words_le::<2>(&bytes), expected);
    }

    #[test]
    fn test_bytes_to_words_le_vec() {
        let bytes = [0x78, 0x56, 0x34, 0x12, 0xEF, 0xCD, 0xAB, 0x90];
        let expected = vec![0x12345678, 0x90ABCDEF];
        assert_eq!(bytes_to_words_le_vec(&bytes), expected);
    }

    #[test]
    fn test_num_to_comma_separated() {
        assert_eq!(num_to_comma_separated(1000), "1,000");
        assert_eq!(num_to_comma_separated(1000000), "1,000,000");
        assert_eq!(num_to_comma_separated(987654321), "987,654,321");

        // Test with a large number as BigUint
        let large_num = num_bigint::BigUint::from(12345678901234567890u64);
        assert_eq!(num_to_comma_separated(large_num), "12,345,678,901,234,567,890");
    }
}
