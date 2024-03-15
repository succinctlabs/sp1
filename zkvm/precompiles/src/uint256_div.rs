use crate::io;
use crate::syscall_uint256_mul;
use crate::unconstrained;
use num::{BigUint, Integer};

/// Uint256 division operation.
pub fn uint256_div(x: &[u8; 32], y: &mut [u8; 32]) -> [u8; 32] {
    cfg_if::cfg_if! {
        if #[cfg(all(target_os = "zkvm", target_vendor = "succinct"))] {
            let dividend = BigUint::from_bytes_le(x);
            let divisor = BigUint::from_bytes_le(y);

            unconstrained!{
                let (quotient, remainder) = dividend.div_rem(&divisor);
                let mut quotient_bytes = quotient.to_bytes_le();
                quotient_bytes.resize(32, 0u8);
                io::hint_slice(&quotient_bytes);

                let mut remainder_bytes = remainder.to_bytes_le();
                remainder_bytes.resize(32, 0u8);
                io::hint_slice(&remainder_bytes);
            };

            let mut quotient_bytes = [0_u8; 32];
            io::read_slice(&mut quotient_bytes);

            let mut remainder_bytes = [0_u8; 32];
            io::read_slice(&mut remainder_bytes);
            let remainder = BigUint::from_bytes_le(&remainder_bytes);

            unsafe {
                syscall_uint256_mul(y.as_mut_ptr() as *mut u32, quotient_bytes.as_mut_ptr() as *mut u32);
            }

            let quotient_times_divisor = BigUint::from_bytes_le(y);
            assert_eq!(quotient_times_divisor, dividend - remainder);

            quotient_bytes
        } else {
            let result_biguint = BigUint::from_bytes_le(x) / BigUint::from_bytes_le(y);
            result_biguint.to_bytes_le().try_into().unwrap_or([0; 32])
        }
    }
}
