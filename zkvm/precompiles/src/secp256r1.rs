use crate::utils::CurveOperations;
use crate::{syscall_secp256r1_add, syscall_secp256r1_double};

#[derive(Copy, Clone)]
pub struct Secp256r1Operations;

impl CurveOperations for Secp256r1Operations {
    // The values are taken from https://neuromancer.sk/std/secg/secp256r1.
    const GENERATOR: [u32; 16] = [
        3633889942, 4104206661, 770388896, 1996717441, 1671708914, 4173129445, 3777774151,
        1796723186, 935285237, 3417718888, 1798397646, 734933847, 2081398294, 2397563722,
        4263149467, 1340293858,
    ];

    fn add_assign(limbs: &mut [u32; 16], other: &[u32; 16]) {
        unsafe {
            syscall_secp256r1_add(limbs.as_mut_ptr(), other.as_ptr());
        }
    }

    fn double(limbs: &mut [u32; 16]) {
        unsafe {
            syscall_secp256r1_double(limbs.as_mut_ptr());
        }
    }
}
