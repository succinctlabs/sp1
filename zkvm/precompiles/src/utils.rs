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

    // expects the bytes to be in little-endian order.
    pub fn from(x_bytes: [u8; 32], y_bytes: [u8; 32]) -> Self {
        let mut limbs = [0; 16];
        for i in 0..8 {
            let x_byte = u32::from_le_bytes(x_bytes[i * 4..(i + 1) * 4].try_into().unwrap());
            let y_byte = u32::from_le_bytes(y_bytes[i * 4..(i + 1) * 4].try_into().unwrap());
            limbs[i] = x_byte;
            limbs[i + 8] = y_byte;
        }
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
        let u32_limbs = limbs
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<u32>>()
            .try_into()
            .unwrap();
        Self {
            limbs: u32_limbs,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn to_le_bytes(&self) -> [u8; 64] {
        self.limbs
            .iter()
            .enumerate()
            .fold([0u8; 64], |mut acc, (i, &limb)| {
                acc[i * 4..(i + 1) * 4].copy_from_slice(&limb.to_le_bytes());
                acc
            })
    }
}
