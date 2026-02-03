#![no_main]
#![allow(unused)]
use num_bigint::BigUint;
use sp1_curves::params::FieldParameters;
use sp1_lib::utils::{AffinePoint, WeierstrassAffinePoint};
use sp1_zkvm::lib::secp256k1::Secp256k1Point;
use sp1_zkvm::syscalls::{syscall_secp256k1_decompress, syscall_secp256k1_double};
sp1_zkvm::entrypoint!(main);

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
    // let mut a_point_clone = a_point.clone();
    // let a_point_clone2 = a_point.clone();
    // let mut a_point_clone3 = a_point.clone();
    // a_point_clone.complete_add_assign(&a_point_clone2);
    // a_point_clone3.double();
    // assert_eq!(
    //     a_point_clone.limbs_ref(),
    //     a_point_clone3.limbs_ref(),
    //     "Adding a point to itself should double the point"
    // );
}

const A: [u8; 64] = [
    152, 23, 248, 22, 91, 129, 242, 89, 217, 40, 206, 45, 219, 252, 155, 2, 7, 11, 135, 206, 149,
    98, 160, 85, 172, 187, 220, 249, 126, 102, 190, 121, 184, 212, 16, 251, 143, 208, 71, 156, 25,
    84, 133, 166, 72, 180, 23, 253, 168, 8, 17, 14, 252, 251, 164, 93, 101, 196, 163, 38, 119, 218,
    58, 72,
];
// 2 * generator.
// 89565891926547004231252920425935692360644145829622209833684329913297188986597
// 12158399299693830322967808612713398636155367887041628176798871954788371653930
const B: [u8; 64] = [
    229, 158, 112, 92, 185, 9, 172, 171, 167, 60, 239, 140, 75, 142, 119, 92, 216, 124, 192, 149,
    110, 64, 69, 48, 109, 125, 237, 65, 148, 127, 4, 198, 42, 229, 207, 80, 169, 49, 100, 35, 225,
    208, 102, 50, 101, 50, 246, 247, 238, 234, 108, 70, 25, 132, 197, 163, 57, 195, 61, 166, 254,
    104, 225, 26,
];
// 3 * generator.
// 112711660439710606056748659173929673102114977341539408544630613555209775888121
// 25583027980570883691656905877401976406448868254816295069919888960541586679410
const C: [u8; 64] = [
    249, 54, 224, 188, 19, 241, 1, 134, 176, 153, 111, 131, 69, 200, 49, 181, 41, 82, 157, 248,
    133, 79, 52, 73, 16, 195, 88, 146, 1, 138, 48, 249, 114, 230, 184, 132, 117, 253, 185, 108, 27,
    35, 194, 52, 153, 169, 0, 101, 86, 243, 55, 42, 230, 55, 227, 15, 20, 232, 45, 99, 15, 123,
    143, 56,
];

#[inline]
fn as_bytes_le(xs: &mut [u64; 8]) -> &mut [u8; 64] {
    #[cfg(not(target_endian = "little"))]
    compile_error!("expected target to be little endian");
    // SAFETY: Arrays are always laid out in the obvious way. Any possible element value is
    // always valid. The pointee types have the same size, and the target of each transmute has
    // finer alignment than the source.
    // Although not a safety invariant, note that the guest target is always little-endian,
    // which was just sanity-checked, so this will always have the expected behavior.
    unsafe { core::mem::transmute::<&mut [u64; 8], &mut [u8; 64]>(xs) }
}

pub fn main() {
    test_weierstrass_add::<Secp256k1Point, { sp1_lib::secp256k1::N }>(
        &A,
        &B,
        &C,
        sp1_curves::weierstrass::secp256k1::Secp256k1BaseField::MODULUS,
    );

    // let compressed_key: [u8; 33] = sp1_zkvm::io::read_vec().try_into().unwrap();
    // let mut decompressed_key: [u64; 8] = [0; 8];
    // as_bytes_le(&mut decompressed_key)[..32].copy_from_slice(&compressed_key[1..]);
    // let is_odd = match compressed_key[0] {
    //     2 => false,
    //     3 => true,
    //     _ => panic!("Invalid compressed key"),
    // };
    // syscall_secp256k1_decompress(&mut decompressed_key, is_odd);

    // let mut result: [u8; 65] = [0; 65];
    // result[0] = 4;
    // result[1..].copy_from_slice(as_bytes_le(&mut decompressed_key));

    // sp1_zkvm::io::commit_slice(&result);

    // generator.
    // 55066263022277343669578718895168534326250603453777594175500187360389116729240
    // 32670510020758816978083085130507043184471273380659243275938904335757337482424
    // let mut a: [u64; 8] = [
    //     0x59_f2_81_5b_16_f8_17_98,
    //     0x29_bf_cd_b2_dc_e2_8d_9,
    //     0x55_a0_62_95_ce_87_0b_07,
    //     0x79_be_66_7e_f9_dc_bb_ac,
    //     0x9c_47_d0_8f_fb_10_d4_b8,
    //     0xfd_17_b4_48_a6_85_54_19,
    //     0x5d_a4_fb_fc_0e_11_08_a8,
    //     0x48_3a_da_77_26_a3_c4_65,
    // ];

    // syscall_secp256k1_double(&mut a);

    // // 2 * generator.
    // // 89565891926547004231252920425935692360644145829622209833684329913297188986597
    // // 12158399299693830322967808612713398636155367887041628176798871954788371653930
    // let b: [u64; 8] = [
    //     0xab_ac_09_b9_5c_70_9e_e5,
    //     0x5c_77_8e_4b_8c_ef_3c_a7,
    //     0x30_45_40_6e_95_c0_7c_d8,
    //     0xc6_04_7f_94_41_ed_7d_6d,
    //     0x23_64_31_a9_50_cf_e5_2a,
    //     0xf7_f6_32_65_32_66_d0_e1,
    //     0xa3_c5_84_19_46_6c_ea_ee,
    //     0x1a_e1_68_fe_a6_3d_c3_39,
    // ];

    // assert_eq!(a, b);
}
