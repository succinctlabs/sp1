#![no_main]

use sp1_zkvm::lib::secp256k1::Secp256k1AffinePoint;
use sp1_zkvm::lib::utils::AffinePoint;
sp1_zkvm::entrypoint!(main);

pub fn main() {
    for _ in 0..4 {
        // generator.
        // 55066263022277343669578718895168534326250603453777594175500187360389116729240
        // 32670510020758816978083085130507043184471273380659243275938904335757337482424
        let a: [u8; 64] = [
            152, 23, 248, 22, 91, 129, 242, 89, 217, 40, 206, 45, 219, 252, 155, 2, 7, 11, 135,
            206, 149, 98, 160, 85, 172, 187, 220, 249, 126, 102, 190, 121, 184, 212, 16, 251, 143,
            208, 71, 156, 25, 84, 133, 166, 72, 180, 23, 253, 168, 8, 17, 14, 252, 251, 164, 93,
            101, 196, 163, 38, 119, 218, 58, 72,
        ];

        // 2 * generator.
        // 89565891926547004231252920425935692360644145829622209833684329913297188986597
        // 12158399299693830322967808612713398636155367887041628176798871954788371653930
        let b: [u8; 64] = [
            229, 158, 112, 92, 185, 9, 172, 171, 167, 60, 239, 140, 75, 142, 119, 92, 216, 124,
            192, 149, 110, 64, 69, 48, 109, 125, 237, 65, 148, 127, 4, 198, 42, 229, 207, 80, 169,
            49, 100, 35, 225, 208, 102, 50, 101, 50, 246, 247, 238, 234, 108, 70, 25, 132, 197,
            163, 57, 195, 61, 166, 254, 104, 225, 26,
        ];

        let mut a_point = Secp256k1AffinePoint::from_le_bytes(&a);
        let b_point = Secp256k1AffinePoint::from_le_bytes(&b);
        a_point.add_assign(&b_point);

        // 3 * generator.
        // 112711660439710606056748659173929673102114977341539408544630613555209775888121
        // 25583027980570883691656905877401976406448868254816295069919888960541586679410
        let c: [u8; 64] = [
            249, 54, 224, 188, 19, 241, 1, 134, 176, 153, 111, 131, 69, 200, 49, 181, 41, 82, 157,
            248, 133, 79, 52, 73, 16, 195, 88, 146, 1, 138, 48, 249, 114, 230, 184, 132, 117, 253,
            185, 108, 27, 35, 194, 52, 153, 169, 0, 101, 86, 243, 55, 42, 230, 55, 227, 15, 20,
            232, 45, 99, 15, 123, 143, 56,
        ];

        assert_eq!(a_point.to_le_bytes(), c);
    }

    // Test all of the potential cases for addition.
    let a: [u8; 64] = [
        152, 23, 248, 22, 91, 129, 242, 89, 217, 40, 206, 45, 219, 252, 155, 2, 7, 11, 135, 206,
        149, 98, 160, 85, 172, 187, 220, 249, 126, 102, 190, 121, 184, 212, 16, 251, 143, 208, 71,
        156, 25, 84, 133, 166, 72, 180, 23, 253, 168, 8, 17, 14, 252, 251, 164, 93, 101, 196, 163,
        38, 119, 218, 58, 72,
    ];
    let a_point = Secp256k1AffinePoint::from_le_bytes(&a);

    // Case 1: Both points are infinity
    let infinity: [u8; 64] = [0u8; 64];
    let orig_infinity = Secp256k1AffinePoint::from_le_bytes(&infinity);
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
    for y in &mut negation.0[sp1_lib::secp256k1::N / 2..] {
        *y = y.wrapping_neg();
    }
    a_point_clone.complete_add_assign(&negation);
    assert_eq!(
        a_point_clone.limbs_ref(),
        &[0; sp1_lib::secp256k1::N],
        "Adding a point to its negation should result in infinity"
    );

    // Case 6: Default addition
    let a: [u8; 64] = [
        152, 23, 248, 22, 91, 129, 242, 89, 217, 40, 206, 45, 219, 252, 155, 2, 7, 11, 135, 206,
        149, 98, 160, 85, 172, 187, 220, 249, 126, 102, 190, 121, 184, 212, 16, 251, 143, 208, 71,
        156, 25, 84, 133, 166, 72, 180, 23, 253, 168, 8, 17, 14, 252, 251, 164, 93, 101, 196, 163,
        38, 119, 218, 58, 72,
    ];

    // 2 * generator.
    // 89565891926547004231252920425935692360644145829622209833684329913297188986597
    // 12158399299693830322967808612713398636155367887041628176798871954788371653930
    let b: [u8; 64] = [
        229, 158, 112, 92, 185, 9, 172, 171, 167, 60, 239, 140, 75, 142, 119, 92, 216, 124, 192,
        149, 110, 64, 69, 48, 109, 125, 237, 65, 148, 127, 4, 198, 42, 229, 207, 80, 169, 49, 100,
        35, 225, 208, 102, 50, 101, 50, 246, 247, 238, 234, 108, 70, 25, 132, 197, 163, 57, 195,
        61, 166, 254, 104, 225, 26,
    ];

    let mut a_point = Secp256k1AffinePoint::from_le_bytes(&a);
    let b_point = Secp256k1AffinePoint::from_le_bytes(&b);
    a_point.complete_add_assign(&b_point);

    // 3 * generator.
    // 112711660439710606056748659173929673102114977341539408544630613555209775888121
    // 25583027980570883691656905877401976406448868254816295069919888960541586679410
    let c: [u8; 64] = [
        249, 54, 224, 188, 19, 241, 1, 134, 176, 153, 111, 131, 69, 200, 49, 181, 41, 82, 157, 248,
        133, 79, 52, 73, 16, 195, 88, 146, 1, 138, 48, 249, 114, 230, 184, 132, 117, 253, 185, 108,
        27, 35, 194, 52, 153, 169, 0, 101, 86, 243, 55, 42, 230, 55, 227, 15, 20, 232, 45, 99, 15,
        123, 143, 56,
    ];
    assert_eq!(a_point.to_le_bytes(), c);

    println!("done");
}
