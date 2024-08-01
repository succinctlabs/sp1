pub trait AffinePoint<const N: usize>: Clone + Sized {
    /// The generator.
    const GENERATOR: [u32; N];

    /// Creates a new [`AffinePoint`] from the given limbs.
    fn new(limbs: [u32; N]) -> Self;

    /// Returns a reference to the limbs.
    fn limbs_ref(&self) -> &[u32; N];

    /// Returns a mutable reference to the limbs.
    fn limbs_mut(&mut self) -> &mut [u32; N];

    /// Creates a new [`AffinePoint`] from the given x and y coordinates.
    ///
    /// The bytes are the concatenated little endian representations of the coordinates.
    fn from(x: &[u8], y: &[u8]) -> Self {
        debug_assert!(x.len() == N * 2);
        debug_assert!(y.len() == N * 2);

        let mut limbs = [0u32; N];
        let x = bytes_to_words_le(x);
        let y = bytes_to_words_le(y);

        debug_assert!(x.len() == N / 2);
        debug_assert!(y.len() == N / 2);

        limbs[..(N / 2)].copy_from_slice(&x);
        limbs[(N / 2)..].copy_from_slice(&y);
        Self::new(limbs)
    }

    /// Creates a new [`AffinePoint`] from the given bytes in little endian.
    fn from_le_bytes(bytes: &[u8]) -> Self {
        let limbs = bytes_to_words_le(bytes);
        debug_assert!(limbs.len() == N);
        Self::new(limbs.try_into().unwrap())
    }

    /// Creates a new [`AffinePoint`] from the given bytes in big endian.
    fn to_le_bytes(&self) -> Vec<u8> {
        let le_bytes = words_to_bytes_le(self.limbs_ref());
        debug_assert!(le_bytes.len() == N * 4);
        le_bytes
    }

    /// Adds the given [`AffinePoint`] to `self`.
    fn add_assign(&mut self, other: &Self);

    /// Doubles `self`.
    fn double(&mut self);

    /// Multiplies `self` by the given scalar.
    fn mul_assign(&mut self, scalar: &[u32]) -> Result<(), MulAssignError> {
        debug_assert!(scalar.len() == N / 2);

        let mut res: Option<Self> = None;
        let mut temp = self.clone();

        let scalar_is_zero = scalar.iter().all(|&words| words == 0);
        if scalar_is_zero {
            return Err(MulAssignError::ScalarIsZero);
        }

        for &words in scalar.iter() {
            for i in 0..32 {
                if (words >> i) & 1 == 1 {
                    match res.as_mut() {
                        Some(res) => res.add_assign(&temp),
                        None => res = Some(temp.clone()),
                    };
                }

                temp.double();
            }
        }

        *self = res.unwrap();
        Ok(())
    }

    /// Performs multi-scalar multiplication (MSM) on slices of bit vectors and points. Note:
    /// a_bits_le and b_bits_le should be in little endian order.
    fn multi_scalar_multiplication(
        a_bits_le: &[bool],
        a: Self,
        b_bits_le: &[bool],
        b: Self,
    ) -> Option<Self> {
        let mut res: Option<Self> = None;
        let mut temp_a = a.clone();
        let mut temp_b = b.clone();
        for (a_bit, b_bit) in a_bits_le.iter().zip(b_bits_le.iter()) {
            if *a_bit {
                match res.as_mut() {
                    Some(res) => res.add_assign(&temp_a),
                    None => res = Some(temp_a.clone()),
                };
            }

            if *b_bit {
                match res.as_mut() {
                    Some(res) => res.add_assign(&temp_b),
                    None => res = Some(temp_b.clone()),
                };
            }

            temp_a.double();
            temp_b.double();
        }
        res
    }
}

/// Errors that can occur during scalar multiplication of an [`AffinePoint`].
#[derive(Debug)]
pub enum MulAssignError {
    ScalarIsZero,
}

/// Converts a slice of words to a byte array in little endian.
pub fn words_to_bytes_le(words: &[u32]) -> Vec<u8> {
    words
        .iter()
        .flat_map(|word| word.to_le_bytes().to_vec())
        .collect::<Vec<_>>()
}

/// Converts a byte array in little endian to a slice of words.
pub fn bytes_to_words_le(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<_>>()
}
