pub trait CurveOperations {
    const GENERATOR: [u32; 16];
    fn add_assign(limbs: &mut [u32; 16], other: &[u32; 16]);
    fn double(limbs: &mut [u32; 16]);
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AffinePoint<C: CurveOperations> {
    pub(crate) limbs: [u32; 16],
    _marker: std::marker::PhantomData<C>,
}

impl<C: CurveOperations + Copy> AffinePoint<C> {
    const GENERATOR: [u32; 16] = C::GENERATOR;

    pub const fn generator_in_affine() -> Self {
        Self {
            limbs: Self::GENERATOR,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn new(limbs: [u32; 16]) -> Self {
        Self {
            limbs,
            _marker: std::marker::PhantomData,
        }
    }

    /// Construct an AffinePoint from the x and y coordinates. The coordinates are expected to be
    /// in little-endian byte order.
    pub fn from(x_bytes: [u8; 32], y_bytes: [u8; 32]) -> Self {
        let mut limbs = [0u32; 16];
        let x = bytes_to_words_le::<8>(&x_bytes);
        let y = bytes_to_words_le::<8>(&y_bytes);
        limbs[..8].copy_from_slice(&x);
        limbs[8..].copy_from_slice(&y);
        Self::new(limbs)
    }

    pub fn add_assign(&mut self, other: &AffinePoint<C>) {
        C::add_assign(&mut self.limbs, &other.limbs);
    }

    pub fn double(&mut self) {
        C::double(&mut self.limbs);
    }

    pub fn mul_assign(&mut self, scalar: &[u32; 8]) {
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

    pub fn from_le_bytes(limbs: [u8; 64]) -> Self {
        let u32_limbs = bytes_to_words_le::<16>(&limbs);
        Self {
            limbs: u32_limbs,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn to_le_bytes(&self) -> [u8; 64] {
        words_to_bytes_le::<64>(&self.limbs)
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
