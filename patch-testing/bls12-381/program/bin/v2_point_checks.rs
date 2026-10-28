#![no_main]

sp1_zkvm::entrypoint!(main);

use bls12_381_v2::{G1Affine, G2Affine};

pub fn main() {
    let mut off_curve_g1 = [0u8; 96];
    off_curve_g1[47] = 1;
    assert!(bool::from(G1Affine::from_uncompressed(&off_curve_g1).is_none()));

    let mut g1_small_torsion = [0u8; 96];
    g1_small_torsion[95] = 2;
    assert!(bool::from(G1Affine::from_uncompressed(&g1_small_torsion).is_none()));

    let mut off_curve_g2 = [0u8; 192];
    off_curve_g2[95] = 1;
    assert!(bool::from(G2Affine::from_uncompressed(&off_curve_g2).is_none()));

    let mut noncanonical_g1 = [0u8; 96];
    noncanonical_g1[..48].fill(0xff);
    noncanonical_g1[0] = 0x1f;
    noncanonical_g1[95] = 2;
    assert!(bool::from(G1Affine::from_uncompressed(&noncanonical_g1).is_none()));
    noncanonical_g1 = [0u8; 96];
    noncanonical_g1[48..].fill(0xff);
    assert!(bool::from(G1Affine::from_uncompressed(&noncanonical_g1).is_none()));

    let mut noncanonical_g2 = [0u8; 192];
    noncanonical_g2[48..96].fill(0xff);
    assert!(bool::from(G2Affine::from_uncompressed(&noncanonical_g2).is_none()));
    noncanonical_g2 = [0u8; 192];
    noncanonical_g2[144..].fill(0xff);
    assert!(bool::from(G2Affine::from_uncompressed(&noncanonical_g2).is_none()));

    let g1 = G1Affine::generator();
    assert_eq!(G1Affine::from_uncompressed(&g1.to_uncompressed()).unwrap(), g1);
    assert_eq!(G1Affine::from_compressed(&g1.to_compressed()).unwrap(), g1);

    let g2 = G2Affine::generator();
    assert_eq!(G2Affine::from_uncompressed(&g2.to_uncompressed()).unwrap(), g2);
    assert_eq!(G2Affine::from_compressed(&g2.to_compressed()).unwrap(), g2);

    let point = <bls12_381_v2::G2Projective as bls12_381_v2::hash_to_curve::HashToCurve<
        bls12_381_v2::hash_to_curve::ExpandMsgXmd<sha2::Sha256>,
    >>::hash_to_curve(
        b"helios v2 compatibility", b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
    );
    let point = G2Affine::from(point);
    assert_eq!(G2Affine::from_compressed(&point.to_compressed()).unwrap(), point);
    sp1_zkvm::io::commit(&true);
}
