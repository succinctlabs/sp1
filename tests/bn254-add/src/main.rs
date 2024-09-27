#![no_main]

use sp1_lib::{utils::AffinePoint, bn254::Bn254AffinePoint};
sp1_zkvm::entrypoint!(main);

// generator.
// 1
// 2
const A: [u8; 64] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0,
];

// 2 * generator.
// 1368015179489954701390400359078579693043519447331113978918064868415326638035
// 9918110051302171585080402603319702774565515993150576347155970296011118125764
const B: [u8; 64] = [
    211, 207, 135, 109, 193, 8, 194, 211, 168, 28, 135, 22, 169, 22, 120, 217, 133, 21, 24,
    104, 91, 4, 133, 155, 2, 26, 19, 46, 231, 68, 6, 3, 196, 162, 24, 90, 122, 191, 62,
    255, 199, 143, 83, 227, 73, 164, 166, 104, 10, 156, 174, 178, 150, 95, 132, 231, 146,
    124, 10, 14, 140, 115, 237, 21,
];

// 3 * generator.
// 3353031288059533942658390886683067124040920775575537747144343083137631628272
// 19321533766552368860946552437480515441416830039777911637913418824951667761761
const C: [u8; 64] = [
    240, 171, 21, 25, 150, 85, 211, 242, 121, 230, 184, 21, 71, 216, 21, 147, 21, 189, 182,
    177, 188, 50, 2, 244, 63, 234, 107, 197, 154, 191, 105, 7, 97, 34, 254, 217, 61, 255,
    241, 205, 87, 91, 156, 11, 180, 99, 158, 49, 117, 100, 8, 141, 124, 219, 79, 85, 41,
    148, 72, 224, 190, 153, 183, 42,
];

pub fn main() {
    // Validate that add_assign works.
    let mut a_point = Bn254AffinePoint::from_le_bytes(&A);
    let b_point = Bn254AffinePoint::from_le_bytes(&B);
    a_point.add_assign(&b_point);
    assert_eq!(a_point.to_le_bytes(), C);

    // Validate that complete_add_assign works. Handles all of the potential special cases.
    // Test all of the potential cases for addition.
    let a_point = Bn254AffinePoint::from_le_bytes(&A);
    let b_point = Bn254AffinePoint::from_le_bytes(&B);

    // Case 1: Both points are infinity
    let infinity: [u8; 64] = [0u8; 64];
    let orig_infinity = Bn254AffinePoint::from_le_bytes(&infinity);
    let mut b = orig_infinity.clone();
    let b2 = orig_infinity.clone();
    b.complete_add_assign(&b2);
    assert_eq!(
        b.limbs_ref(),
        orig_infinity.limbs_ref(),
        "Adding two infinity points should result in infinity"
    );

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

    // Case 5: Points are negations of each other
    let mut a_point_clone = a_point.clone();
    // Create a point that is the negation of a_point
    let mut negation = a_point.clone();
    // Negate the y-coordinate
    for y in &mut negation.0[sp1_lib::bn254::N / 2..] {
        *y = y.wrapping_neg();
    }
    a_point_clone.complete_add_assign(&negation);
    assert_eq!(
        a_point_clone.limbs_ref(),
        &[0; sp1_lib::bn254::N],
        "Adding a point to its negation should result in infinity"
    );

    // Case 6: Default addition
    let mut a_point_clone = a_point.clone();
    a_point_clone.complete_add_assign(&b_point);
    assert_eq!(a_point_clone.to_le_bytes(), C);

    println!("done");
}

