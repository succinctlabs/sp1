use core::arch::x86_64::{
    __m128i, _mm_clmulepi64_si128, _mm_extract_epi64, _mm_set_epi64x, _mm_xor_si128,
};

use super::{GHash, GHashUnreduced};

#[inline]
#[target_feature(enable = "pclmulqdq,sse4.1")]
unsafe fn carryless_multiply(lhs: u64, rhs: u64) -> __m128i {
    _mm_clmulepi64_si128::<0x00>(_mm_set_epi64x(0, lhs as i64), _mm_set_epi64x(0, rhs as i64))
}

#[inline]
#[target_feature(enable = "sse4.1")]
unsafe fn low(value: __m128i) -> u64 {
    _mm_extract_epi64::<0>(value) as u64
}

#[inline]
#[target_feature(enable = "sse4.1")]
unsafe fn high(value: __m128i) -> u64 {
    _mm_extract_epi64::<1>(value) as u64
}

#[target_feature(enable = "pclmulqdq,sse4.1")]
pub(super) unsafe fn multiply(lhs: GHash, rhs: GHash) -> GHash {
    let low_product = unsafe { carryless_multiply(lhs.lo, rhs.lo) };
    let high_product = unsafe { carryless_multiply(lhs.hi, rhs.hi) };
    let middle_product = unsafe { carryless_multiply(lhs.lo ^ lhs.hi, rhs.lo ^ rhs.hi) };
    let cross_product = _mm_xor_si128(_mm_xor_si128(middle_product, low_product), high_product);

    let product_low = unsafe { low(low_product) };
    let product_high = unsafe { high(low_product) ^ low(cross_product) };
    let overflow_low = unsafe { low(high_product) ^ high(cross_product) };
    let overflow_high = unsafe { high(high_product) };

    let reduced_high = unsafe { carryless_multiply(overflow_high, 0x87) };
    let reduced_low = unsafe { carryless_multiply(overflow_low, 0x87) };
    let overflow = unsafe { high(reduced_high) };
    let correction = overflow ^ (overflow << 1) ^ (overflow << 2) ^ (overflow << 7);

    GHash {
        lo: product_low ^ unsafe { low(reduced_low) } ^ correction,
        hi: product_high ^ unsafe { high(reduced_low) ^ low(reduced_high) },
    }
}

#[target_feature(enable = "pclmulqdq,sse4.1")]
pub(super) unsafe fn multiply_unreduced(lhs: GHash, rhs: GHash) -> GHashUnreduced {
    let low_product = unsafe { carryless_multiply(lhs.lo, rhs.lo) };
    let low_high_product = unsafe { carryless_multiply(lhs.lo, rhs.hi) };
    let high_low_product = unsafe { carryless_multiply(lhs.hi, rhs.lo) };
    let high_product = unsafe { carryless_multiply(lhs.hi, rhs.hi) };
    let cross_product = _mm_xor_si128(low_high_product, high_low_product);

    GHashUnreduced {
        limbs: [
            unsafe { low(low_product) },
            unsafe { high(low_product) ^ low(cross_product) },
            unsafe { low(high_product) ^ high(cross_product) },
            unsafe { high(high_product) },
        ],
    }
}
