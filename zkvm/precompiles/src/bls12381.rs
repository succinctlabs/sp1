use crate::utils::CurveOperations;
use crate::{syscall_bls12381_add, syscall_bls12381_double};

#[derive(Copy, Clone)]
pub struct Bls12381;

const NUM_WORDS: usize = 24;

impl CurveOperations<NUM_WORDS> for Bls12381 {
    // The generator has been taken from py_ecc python library by Ethereum Foundation.
    // https://github.com/ethereum/py_ecc/blob/7b9e1b3/py_ecc/bls12_381/bls12_381_curve.py#L38-L45
    const GENERATOR: [u32; NUM_WORDS] = [
        3676489403, 4214943754, 4185529071, 1817569343, 387689560, 2706258495, 2541009157,
        3278408783, 1336519695, 647324556, 832034708, 401724327, 1187375073, 212476713, 2726857444,
        3493644100, 738505709, 14358731, 3587181302, 4243972245, 1948093156, 2694721773,
        3819610353, 146011265,
    ];

    fn add_assign(limbs: &mut [u32; NUM_WORDS], other: &[u32; NUM_WORDS]) {
        unsafe {
            syscall_bls12381_add(limbs.as_mut_ptr(), other.as_ptr());
        }
    }

    fn double(limbs: &mut [u32; NUM_WORDS]) {
        unsafe {
            syscall_bls12381_double(limbs.as_mut_ptr());
        }
    }
}
