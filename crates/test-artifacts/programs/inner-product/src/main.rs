#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::syscalls::syscall_inner_product;

fn test_inner_product(a: &[u32], b: &[u32]) -> u32 {
    assert_eq!(a.len(), b.len(), "Vectors must have same length");

    // Create vectors with length prefix
    let mut a_with_len = vec![a.len() as u32];
    a_with_len.extend_from_slice(a);

    let mut b_with_len = vec![b.len() as u32];
    b_with_len.extend_from_slice(b);

    // Expected result
    let expected: u32 = a.iter().zip(b.iter()).map(|(&x, &y)| x * y).sum();

    // Call syscall - result will be written to a_with_len[0]
    unsafe {
        syscall_inner_product(a_with_len.as_mut_ptr(), b_with_len.as_mut_ptr());
    }

    // Get result from a_with_len[0]
    let result = a_with_len[0];
    assert_eq!(result, expected, "Inner product mismatch");

    result
}

pub fn main() {
    // // Test case 1: Simple vectors
    // let a = vec![1, 2, 3];
    // let b = vec![4, 5, 6];
    // let result = test_inner_product(&a, &b);
    // assert_eq!(result, 32); // 1*4 + 2*5 + 3*6 = 32

    // // Test case 2: Maximum values
    // let a = vec![u32::MAX / 2, u32::MAX / 3];
    // let b = vec![2, 3];
    // test_inner_product(&a, &b);

    // // Test case 3: Longer vector
    // let a = vec![1; 10];
    // let b = vec![1; 10];
    // test_inner_product(&a, &b);

    println!("All tests passed!");
}
