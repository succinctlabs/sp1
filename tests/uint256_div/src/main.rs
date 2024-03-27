#![no_main]
sp1_zkvm::entrypoint!(main);

use core::panic::AssertUnwindSafe;
use num::BigUint;
use rand::Rng;
use std::panic;

use sp1_zkvm::precompiles::uint256_div::uint256_div;

#[sp1_derive::cycle_tracker]
fn main() {
    // Random test.
    for _ in 0..10 {
        // generate random dividend and divisor.
        let mut rng = rand::thread_rng();
        let mut dividend: [u8; 32] = rng.gen();
        let divisor: [u8; 32] = rng.gen();

        // Skip division by zero
        if divisor == [0; 32] {
            continue;
        }
        // println!("Dividend: {} {:?}", dividend.len(), dividend);
        // println!("Divisor: {} {:?}", divisor.len(), divisor);
        // Convert byte arrays to BigUint for validation.
        let dividend_big = BigUint::from_bytes_le(&dividend);
        let divisor_big = BigUint::from_bytes_le(&divisor);

        // Perform division.
        let quotient = uint256_div(&mut dividend, &divisor);

        let quotient_big = BigUint::from_bytes_le(&quotient);
        let product = &quotient_big * &divisor_big;

        // Check if the product of quotient and divisor equals the dividend
        assert_eq!(
            product, dividend_big,
            "Quotient times divisor should equal dividend."
        );
    }

    // Hardcoded edge case: division by 1.
    let mut rng = rand::thread_rng();
    let mut dividend: [u8; 32] = rng.gen();
    let mut divisor = [0; 32];

    // Least significant byte set to 1, represents the number 1.
    divisor[0] = 3;

    let expected_quotient: [u8; 32] = dividend.clone();

    let quotient = uint256_div(&mut dividend, &divisor);
    assert_eq!(
        quotient, expected_quotient,
        "Dividing by 1 should yield the same number."
    );

    println!("All tests passed.");
}

// pub fn main() {
//     // 24
//     let mut dividend: [u8; 32] = [
//         24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//         0, 0,
//     ];

//     // 5
//     let divisor: [u8; 32] = [
//         5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//         0, 0,
//     ];

//     println!("cycle-tracker-start: uint256_div");
//     let quotient = uint256_div(&mut dividend, &divisor);
//     println!("cycle-tracker-end: uint256_div");
//     io::write_slice(&quotient);

//     let c: [u8; 32] = [
//         4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//         0, 0,
//     ];

//     assert_eq!(quotient, c);
//     println!("done");
// }
