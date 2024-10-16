pub trait AffinePoint<const N: usize>: Clone + Sized {
    /// The generator.
    const GENERATOR: [u32; N];

    /// Creates a new [`AffinePoint`] from the given limbs.
    fn new(limbs: [u32; N]) -> Self;

    /// Returns a reference to the limbs.
    fn limbs_ref(&self) -> &[u32; N];

    /// Returns a mutable reference to the limbs. If the point is the infinity point, this will panic.
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

    /// Adds the given [`AffinePoint`] to `self`. Can be optionally overridden to use a different
    /// implementation of addition in multi-scalar multiplication, which is used in secp256k1 recovery.
    fn complete_add_assign(&mut self, other: &Self) {
        self.add_assign(other);
    }

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
        // The length of the bit vectors must be the same.
        debug_assert!(a_bits_le.len() == b_bits_le.len());

        let mut res: Option<Self> = None;
        let mut temp_a = a.clone();
        let mut temp_b = b.clone();
        for (a_bit, b_bit) in a_bits_le.iter().zip(b_bits_le.iter()) {
            if *a_bit {
                match res.as_mut() {
                    Some(res) => res.complete_add_assign(&temp_a),
                    None => res = Some(temp_a.clone()),
                };
            }

            if *b_bit {
                match res.as_mut() {
                    Some(res) => res.complete_add_assign(&temp_b),
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
    words.iter().flat_map(|word| word.to_le_bytes().to_vec()).collect::<Vec<_>>()
}

/// Converts a byte array in little endian to a slice of words.
pub fn bytes_to_words_le(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<_>>()
}

#[derive(Copy, Clone)]
/// A representation of a point on a Weierstrass curve.
pub enum WeierstrassPoint<const N: usize> {
    Infinity,
    Affine([u32; N]),
}

/// A trait for affine points on Weierstrass curves.
pub trait WeierstrassAffinePoint<const N: usize>: AffinePoint<N> {
    /// The infinity point representation of the Weierstrass curve. Typically an enum variant.
    fn infinity() -> Self;

    /// Returns true if the point is the infinity point.
    fn is_infinity(&self) -> bool;

    /// Performs the complete addition of two [`AffinePoint`]'s on a Weierstrass curve.
    /// For an addition of two points P1 and P2, the cases are:
    ///     1. P1 is infinity
    ///     2. P2 is infinity
    ///     3. P1 equals P2
    ///     4. P1 is the negation of P2
    ///     5. Default addition.
    ///
    /// Implements the complete addition cases according to the
    /// [Zcash complete addition spec](https://zcash.github.io/halo2/design/gadgets/ecc/addition.html#complete-addition).
    fn weierstrass_add_assign(&mut self, other: &Self) {
        // Case 1: p1 is infinity.
        if self.is_infinity() {
            *self = other.clone();
            return;
        }

        // Case 2: p2 is infinity.
        if other.is_infinity() {
            return;
        }

        // Once it's known the points are not infinity, their limbs can be safely used.
        let p1 = self.limbs_mut();
        let p2 = other.limbs_ref();

        // Case 3: p1 equals p2.
        if p1 == p2 {
            self.double();
            return;
        }

        // Case 4: p1 is the negation of p2.
        // Note: If p1 and p2 are valid elliptic curve points, and p1.x == p2.x, that means that
        // either p1.y == p2.y or p1.y + p2.y == p. Because we are past Case 4, we know that p1.y !=
        // p2.y, so we can just check if p1.x == p2.x. Therefore, this implicitly checks that
        // p1.x == p2.x AND p1.y + p2.y == p without modular negation.
        if p1[..N / 2] == p2[..N / 2] {
            *self = Self::infinity();
            return;
        }

        // Case 5: Default addition.
        self.add_assign(other);
    }
}
