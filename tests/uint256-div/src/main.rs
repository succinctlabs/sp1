#![no_main]
sp1_zkvm::entrypoint!(main);

use num::BigUint;
use rand::Rng;

use sp1_zkvm::precompiles::uint256_div::uint256_div;

#[sp1_derive::cycle_tracker]
fn main() {
    // Random test.
    for _ in 0..100 {
        // generate random dividend and divisor.
        let mut rng = rand::thread_rng();
        let mut dividend: [u8; 32] = rng.gen();
        let divisor: [u8; 32] = rng.gen();

        // Skip division by zero
        if divisor == [0; 32] {
            continue;
        }

        // Convert byte arrays to BigUint for validation.
        let dividend_big = BigUint::from_bytes_le(&dividend);
        let divisor_big = BigUint::from_bytes_le(&divisor);

        let quotient_big = &dividend_big / &divisor_big;

        // Perform division.
        let quotient = uint256_div(&mut dividend, &divisor);

        let quotient_precompile_big = BigUint::from_bytes_le(&quotient);

        // Check if the product of quotient and divisor equals the dividend
        assert_eq!(
            quotient_precompile_big, quotient_big,
            "Quotient should match."
        );
    }

    // Hardcoded edge case: division by 1.
    let mut rng = rand::thread_rng();
    let mut dividend: [u8; 32] = rng.gen();
    let mut divisor = [0; 32];
    divisor[0] = 1;

    let expected_quotient: [u8; 32] = dividend.clone();

    let quotient = uint256_div(&mut dividend, &divisor);
    assert_eq!(
        quotient, expected_quotient,
        "Dividing by 1 should yield the same number."
    );

    // Hardcoded edge case: when the dividend is smaller thant the divisor.
    // In this case, the quotient should be zero.
    let mut dividend = [0; 32];
    dividend[0] = 1;
    let mut divisor = [0; 32];
    divisor[0] = 4;

    let expected_quotient: [u8; 32] = [0; 32];

    let quotient = uint256_div(&mut dividend, &divisor);
    assert_eq!(
        quotient, expected_quotient,
        "The quotient should be zero when the dividend is smaller than the divisor."
    );

    println!("All tests passed.");
}
