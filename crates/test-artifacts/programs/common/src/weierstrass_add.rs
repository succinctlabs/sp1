use num_bigint::BigUint;
use sp1_lib::utils::{AffinePoint, WeierstrassAffinePoint};

/// Test all of the potential special cases for addition for Weierstrass elliptic curves.
pub fn test_weierstrass_add<P: AffinePoint<N> + WeierstrassAffinePoint<N>, const N: usize>(
    a: &[u8],
    b: &[u8],
    c: &[u8],
    modulus: &[u8],
) {
    // Validate that add_assign works.
    let mut a_point = P::from_le_bytes(a);
    let b_point = P::from_le_bytes(b);
    a_point.add_assign(&b_point);
    assert_eq!(a_point.to_le_bytes(), *c);

    // Validate that complete_add_assign works. Handles all of the potential special cases.
    // Test all of the potential cases for addition.
    let a_point = P::from_le_bytes(a);
    let b_point = P::from_le_bytes(b);

    // Case 1: Both points are infinity
    let orig_infinity = P::infinity();
    let mut b = orig_infinity.clone();
    let b2 = orig_infinity.clone();
    b.complete_add_assign(&b2);
    assert!(b.is_infinity(), "Adding two infinity points should result in infinity");

    // Case 2: First point is infinity
    let mut b = orig_infinity.clone();
    b.complete_add_assign(&a_point);
    assert_eq!(
        b.limbs_ref(),
        a_point.limbs_ref(),
        "Adding infinity to a point should result in that point"
    );

    // Case 3: Second point is infinity
    let mut a_point_clone = a_point.clone();
    let b = orig_infinity.clone();
    a_point_clone.complete_add_assign(&b);
    assert_eq!(
        a_point_clone.limbs_ref(),
        a_point.limbs_ref(),
        "Adding a point to infinity should result in that point"
    );

    // Case 4: Points are equal (point doubling, already covered by the main loop)
    let mut a_point_clone = a_point.clone();
    let a_point_clone2 = a_point.clone();
    let mut a_point_clone3 = a_point.clone();
    a_point_clone.complete_add_assign(&a_point_clone2);
    a_point_clone3.double();
    assert_eq!(
        a_point_clone.limbs_ref(),
        a_point_clone3.limbs_ref(),
        "Adding a point to itself should double the point"
    );

    // Case 5: Points are negations of each other.
    // Create a point that is the negation of a_point.
    let a_point_le_bytes = a_point.to_le_bytes();
    let y_biguint = BigUint::from_bytes_le(&a_point_le_bytes[N * 2..]);
    let modulus_biguint = BigUint::from_bytes_le(modulus);

    // Negate y.
    let negated_y_biguint = (&modulus_biguint - &y_biguint) % &modulus_biguint;

    // Create a point using the negated y.
    let mut combined_negation_point_bytes = a_point_le_bytes[..N * 2].to_vec();
    combined_negation_point_bytes.extend_from_slice(&negated_y_biguint.to_bytes_le());
    let negation_point = P::from_le_bytes(&combined_negation_point_bytes);

    let mut a_point_clone = a_point.clone();
    a_point_clone.complete_add_assign(&negation_point);
    assert!(
        a_point_clone.is_infinity(),
        "Adding a point to its negation should result in infinity"
    );

    // Case 6: Default addition
    let mut a_point_clone = a_point.clone();
    a_point_clone.complete_add_assign(&b_point);
    assert_eq!(a_point_clone.to_le_bytes(), *c);
}
