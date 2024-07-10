pub trait CurveOperations<const NUM_WORDS: usize> {
    const GENERATOR: [u32; NUM_WORDS];

    fn add_assign(limbs: &mut [u32; NUM_WORDS], other: &[u32; NUM_WORDS]);
    fn double(limbs: &mut [u32; NUM_WORDS]);
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AffinePoint<C: CurveOperations<NUM_WORDS>, const NUM_WORDS: usize> {
    pub(crate) limbs: [u32; NUM_WORDS],
    _marker: std::marker::PhantomData<C>,
}

#[derive(Debug)]
pub enum MulAssignError {
    ZeroScalar,
}

impl<C: CurveOperations<NUM_WORDS> + Copy, const NUM_WORDS: usize> AffinePoint<C, NUM_WORDS> {
    const GENERATOR: [u32; NUM_WORDS] = C::GENERATOR;

    pub const fn generator_in_affine() -> Self {
        Self {
            limbs: Self::GENERATOR,
            _marker: std::marker::PhantomData,
        }
    }

    pub const fn new(limbs: [u32; NUM_WORDS]) -> Self {
        Self {
            limbs,
            _marker: std::marker::PhantomData,
        }
    }

    /// x_bytes and y_bytes are the concatenated little endian representations of the x and y coordinates.
    /// The length of x_bytes and y_bytes must each be NUM_WORDS * 2.
    pub fn from(x_bytes: &[u8], y_bytes: &[u8]) -> Self {
        debug_assert!(x_bytes.len() == NUM_WORDS * 2);
        debug_assert!(y_bytes.len() == NUM_WORDS * 2);

        let mut limbs = [0u32; NUM_WORDS];
        let x = bytes_to_words_le(x_bytes);
        let y = bytes_to_words_le(y_bytes);
        debug_assert!(x.len() == NUM_WORDS / 2);
        debug_assert!(y.len() == NUM_WORDS / 2);

        limbs[..(NUM_WORDS / 2)].copy_from_slice(&x);
        limbs[(NUM_WORDS / 2)..].copy_from_slice(&y);
        Self::new(limbs)
    }

    pub fn add_assign(&mut self, other: &AffinePoint<C, NUM_WORDS>) {
        C::add_assign(&mut self.limbs, &other.limbs);
    }

    pub fn double(&mut self) {
        C::double(&mut self.limbs);
    }

    pub fn mul_assign(&mut self, scalar: &[u32]) -> Result<(), MulAssignError> {
        debug_assert!(scalar.len() == NUM_WORDS / 2);

        let mut res: Option<Self> = None;
        let mut temp = *self;

        let scalar_is_zero = scalar.iter().all(|&words| words == 0);
        if scalar_is_zero {
            return Err(MulAssignError::ZeroScalar);
        }

        for &words in scalar.iter() {
            for i in 0..32 {
                if (words >> i) & 1 == 1 {
                    match res.as_mut() {
                        Some(res) => res.add_assign(&temp),
                        None => res = Some(temp),
                    };
                }

                temp.double();
            }
        }

        *self = res.unwrap();
        Ok(())
    }

    pub fn from_le_bytes(limbs: &[u8]) -> Self {
        let u32_limbs = bytes_to_words_le(limbs);
        debug_assert!(u32_limbs.len() == NUM_WORDS);

        Self {
            limbs: u32_limbs.try_into().unwrap(),
            _marker: std::marker::PhantomData,
        }
    }

    pub fn to_le_bytes(&self) -> Vec<u8> {
        let le_bytes = words_to_bytes_le(&self.limbs);
        debug_assert!(le_bytes.len() == NUM_WORDS * 4);
        le_bytes
    }
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
