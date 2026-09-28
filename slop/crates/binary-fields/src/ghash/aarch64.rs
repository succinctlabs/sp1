use core::{
    arch::aarch64::{uint64x2_t, vdupq_n_u64, veorq_u64, vextq_u64, vgetq_lane_u64, vmull_p64},
    mem::transmute,
};

use super::{GHash, GHashUnreduced};

#[inline]
#[target_feature(enable = "aes")]
unsafe fn carryless_multiply(lhs: u64, rhs: u64) -> uint64x2_t {
    let product = vmull_p64(lhs, rhs);
    // SAFETY: Both types have the same size and alignment.
    unsafe { transmute::<u128, uint64x2_t>(product) }
}

#[target_feature(enable = "aes")]
pub(super) unsafe fn multiply(lhs: GHash, rhs: GHash) -> GHash {
    let zero = vdupq_n_u64(0);
    let low_product = unsafe { carryless_multiply(lhs.lo, rhs.lo) };
    let low_high_product = unsafe { carryless_multiply(lhs.lo, rhs.hi) };
    let high_low_product = unsafe { carryless_multiply(lhs.hi, rhs.lo) };
    let high_product = unsafe { carryless_multiply(lhs.hi, rhs.hi) };
    let mut cross_product = veorq_u64(low_high_product, high_low_product);

    cross_product = veorq_u64(cross_product, vextq_u64::<1>(zero, high_product));
    cross_product = veorq_u64(cross_product, unsafe {
        carryless_multiply(vgetq_lane_u64::<1>(high_product), 0x87)
    });

    let mut result = veorq_u64(low_product, vextq_u64::<1>(zero, cross_product));
    result =
        veorq_u64(result, unsafe { carryless_multiply(vgetq_lane_u64::<1>(cross_product), 0x87) });

    GHash { lo: vgetq_lane_u64::<0>(result), hi: vgetq_lane_u64::<1>(result) }
}

#[target_feature(enable = "aes")]
pub(super) unsafe fn multiply_unreduced(lhs: GHash, rhs: GHash) -> GHashUnreduced {
    let low_product = unsafe { carryless_multiply(lhs.lo, rhs.lo) };
    let low_high_product = unsafe { carryless_multiply(lhs.lo, rhs.hi) };
    let high_low_product = unsafe { carryless_multiply(lhs.hi, rhs.lo) };
    let high_product = unsafe { carryless_multiply(lhs.hi, rhs.hi) };
    let cross_product = veorq_u64(low_high_product, high_low_product);

    GHashUnreduced {
        limbs: [
            vgetq_lane_u64::<0>(low_product),
            vgetq_lane_u64::<1>(low_product) ^ vgetq_lane_u64::<0>(cross_product),
            vgetq_lane_u64::<0>(high_product) ^ vgetq_lane_u64::<1>(cross_product),
            vgetq_lane_u64::<1>(high_product),
        ],
    }
}
