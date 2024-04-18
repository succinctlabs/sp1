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

impl<C: CurveOperations<NUM_WORDS> + Copy, const NUM_WORDS: usize> AffinePoint<C, NUM_WORDS> {
    const GENERATOR: [u32; NUM_WORDS] = C::GENERATOR;

    pub const fn generator_in_affine() -> Self {
        Self {
            limbs: Self::GENERATOR,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn new(limbs: [u32; NUM_WORDS]) -> Self {
        Self {
            limbs,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn from(x_bytes: [u8; NUM_WORDS * 2], y_bytes: [u8; NUM_WORDS * 2]) -> Self
    where
        [(); NUM_WORDS / 2]:,
    {
        let mut limbs = [0u32; NUM_WORDS];
        let x = bytes_to_words_le::<{ NUM_WORDS / 2 }>(&x_bytes);
        let y = bytes_to_words_le::<{ NUM_WORDS / 2 }>(&y_bytes);
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

    pub fn mul_assign(&mut self, scalar: &[u32; NUM_WORDS / 2]) {
        let mut res: Option<Self> = None;
        let mut temp = *self;

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
    }

    pub fn from_le_bytes(limbs: [u8; NUM_WORDS * 4]) -> Self {
        let u32_limbs = bytes_to_words_le::<{ NUM_WORDS }>(&limbs);
        Self {
            limbs: u32_limbs,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn to_le_bytes(&self) -> [u8; NUM_WORDS * 4] {
        words_to_bytes_le::<{ NUM_WORDS * 4 }>(&self.limbs)
    }
}

/// Converts a slice of words to a byte array in little endian.
pub fn words_to_bytes_le<const B: usize>(words: &[u32]) -> [u8; B] {
    debug_assert_eq!(words.len() * 4, B);
    words
        .iter()
        .flat_map(|word| word.to_le_bytes().to_vec())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

/// Converts a byte array in little endian to a slice of words.
pub fn bytes_to_words_le<const W: usize>(bytes: &[u8]) -> [u32; W] {
    debug_assert_eq!(bytes.len(), W * 4);
    bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}
