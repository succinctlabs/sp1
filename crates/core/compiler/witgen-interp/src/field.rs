//! Prime-field arithmetic behind a minimal trait.
//!
//! The wire format needs exactly: `+`, `·`, inverse **with `0⁻¹ = 0`**, the canonical
//! value (for `val`/`lt`/`bit`/`bitsOf`), and value-to-element (for `ofU64` and
//! constants; on a prime field this is reduction mod p). There is no subtraction node
//! on the wire (`x - y` arrives as `x + (p-1)·y`), so the trait carries none.

pub trait Field: Copy + Eq + std::fmt::Debug {
    const MODULUS: u64;
    /// Reduce an arbitrary value into the field.
    fn from_u64(n: u64) -> Self;
    /// The canonical value, `0 ≤ val < MODULUS`.
    fn val(self) -> u64;
    fn add(self, other: Self) -> Self;
    fn mul(self, other: Self) -> Self;
    /// Multiplicative inverse, with `0⁻¹ = 0` (the total-evaluation convention).
    fn inv(self) -> Self;
    fn zero() -> Self {
        Self::from_u64(0)
    }
}

/// KoalaBear, `p = 2^31 - 2^24 + 1`. `p < 2^31`, so sums and products fit in `u64`
/// with naive reduction — a reference interpreter needs no Montgomery form.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct KoalaBear(u32);

impl KoalaBear {
    fn pow(self, mut e: u64) -> Self {
        let mut base = self;
        let mut acc = Self::from_u64(1);
        while e > 0 {
            if e & 1 == 1 {
                acc = acc.mul(base);
            }
            base = base.mul(base);
            e >>= 1;
        }
        acc
    }
}

impl Field for KoalaBear {
    const MODULUS: u64 = 2_130_706_433;

    fn from_u64(n: u64) -> Self {
        KoalaBear((n % Self::MODULUS) as u32)
    }

    fn val(self) -> u64 {
        self.0 as u64
    }

    fn add(self, other: Self) -> Self {
        Self::from_u64(self.0 as u64 + other.0 as u64)
    }

    fn mul(self, other: Self) -> Self {
        Self::from_u64(self.0 as u64 * other.0 as u64)
    }

    fn inv(self) -> Self {
        if self.0 == 0 {
            return self; // 0⁻¹ = 0
        }
        self.pow(Self::MODULUS - 2) // Fermat
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inv_zero_is_zero() {
        assert_eq!(KoalaBear::from_u64(0).inv(), KoalaBear::from_u64(0));
    }

    #[test]
    fn inv_is_inverse() {
        for v in [1u64, 2, 65535, 2_130_706_432, 123_456_789] {
            let x = KoalaBear::from_u64(v);
            assert_eq!(x.mul(x.inv()).val(), 1, "v = {v}");
        }
    }

    #[test]
    fn from_u64_reduces() {
        assert_eq!(KoalaBear::from_u64(KoalaBear::MODULUS).val(), 0);
        assert_eq!(
            KoalaBear::from_u64(u64::MAX).val(),
            u64::MAX % KoalaBear::MODULUS
        );
    }

    #[test]
    fn minus_one_encodes_subtraction() {
        // x - y on the wire is x + (p-1)·y
        let x = KoalaBear::from_u64(10);
        let y = KoalaBear::from_u64(3);
        let minus_one = KoalaBear::from_u64(KoalaBear::MODULUS - 1);
        assert_eq!(x.add(minus_one.mul(y)).val(), 7);
    }
}
