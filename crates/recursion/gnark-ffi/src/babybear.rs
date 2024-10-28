// Import necessary modules from the `p3_baby_bear` and `p3_field` crates
use p3_baby_bear::BabyBear;
use p3_field::{
    extension::BinomialExtensionField, AbstractExtensionField, AbstractField, Field, PrimeField32,
};

// Extern function to compute the inverse of a binomial extension field element
#[no_mangle]
pub extern "C" fn babybearextinv(a: u32, b: u32, c: u32, d: u32, i: u32) -> u32 {
    // Convert input u32 values into BabyBear elements
    let a = BabyBear::from_wrapped_u32(a);
    let b = BabyBear::from_wrapped_u32(b);
    let c = BabyBear::from_wrapped_u32(c);
    let d = BabyBear::from_wrapped_u32(d);

    // Create a binomial extension field element from the BabyBear values
    let inv = BinomialExtensionField::<BabyBear, 4>::from_base_slice(&[a, b, c, d]).inverse();

    // Extract the canonical representation of the inverse element as a slice
    let inv: &[BabyBear] = inv.as_base_slice();

    // Return the i-th element of the inverse as a u32
    inv[i as usize].as_canonical_u32()
}

// Extern function to compute the inverse of a single BabyBear element
#[no_mangle]
pub extern "C" fn babybearinv(a: u32) -> u32 {
    // Convert the input u32 into a BabyBear element
    let a = BabyBear::from_wrapped_u32(a);

    // Compute and return the canonical representation of the inverse
    a.inverse().as_canonical_u32()
}

// Unit tests for the functions
#[cfg(test)]
pub mod test {
    use super::babybearextinv;

    // Test case for the babybearextinv function
    #[test]
    fn test_babybearextinv() {
        // Call the function with test values
        let result = babybearextinv(1, 2, 3, 4, 0);
        
        // Here you would typically add assertions to validate the result
        // For example, assert_eq!(result, expected_value);
    }
}
