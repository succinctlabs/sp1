use crate::utils::CurveOperations;
use crate::{syscall_bn254_add, syscall_bn254_double};

#[derive(Copy, Clone)]
pub struct Bn254;

const NUM_WORDS: usize = 16;

impl CurveOperations<NUM_WORDS> for Bn254 {
    /// The generator has been taken from py_pairing python library by the Ethereum Foundation:
    ///
    /// https://github.com/ethereum/py_pairing/blob/5f609da/py_ecc/bn128/bn128_field_elements.py
    const GENERATOR: [u32; NUM_WORDS] = [1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0];

    fn add_assign(limbs: &mut [u32; NUM_WORDS], other: &[u32; NUM_WORDS]) {
        unsafe {
            syscall_bn254_add(limbs.as_mut_ptr(), other.as_ptr());
        }
    }

    fn double(limbs: &mut [u32; NUM_WORDS]) {
        unsafe {
            syscall_bn254_double(limbs.as_mut_ptr());
        }
    }
}
