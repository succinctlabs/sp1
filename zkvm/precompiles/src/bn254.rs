use crate::utils::CurveOperations;
use crate::{syscall_bn254_add, syscall_bn254_double};

#[derive(Copy, Clone)]
pub struct Bn254;

impl CurveOperations for Bn254 {
    const GENERATOR: [u32; 16] = [1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0];

    fn add_assign(limbs: &mut [u32; 16], other: &[u32; 16]) {
        unsafe {
            syscall_bn254_add(limbs.as_mut_ptr(), other.as_ptr());
        }
    }

    fn double(limbs: &mut [u32; 16]) {
        unsafe {
            syscall_bn254_double(limbs.as_mut_ptr());
        }
    }
}
