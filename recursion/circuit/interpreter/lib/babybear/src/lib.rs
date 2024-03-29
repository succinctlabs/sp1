extern crate p3_baby_bear;
extern crate p3_field;

use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;
use p3_field::{extension::BinomialExtensionField, AbstractExtensionField, AbstractField, Field};
use std::ffi::CStr;

#[no_mangle]
pub extern "C" fn babybearextinv(a: u32, b: u32, c: u32, d: u32) -> u32 {
    let a = BabyBear::from_canonical_u32(a);
    let b = BabyBear::from_canonical_u32(b);
    let c = BabyBear::from_canonical_u32(c);
    let d = BabyBear::from_canonical_u32(d);
    let inv = BinomialExtensionField::<BabyBear, 4>::from_base_slice(&[a, b, c, d]).inverse();
    let inv: &[BabyBear] = inv.as_base_slice();
    inv[0].as_canonical_u32()
}

#[no_mangle]
pub extern "C" fn whisper(message: *const libc::c_char) {
    let message_cstr = unsafe { CStr::from_ptr(message) };
    let message = message_cstr.to_str().unwrap();
    println!("({})", message);
}

// This is present so it's easy to test that the code works natively in Rust via `cargo test`
#[cfg(test)]
pub mod test {

    use super::*;

    // This is meant to do the same stuff as the main function in the .go files
    #[test]
    fn simulated_main_function() {
        baby_bear_ext_inv(1, 2, 3, 4);
    }
}
