#![no_main]
sp1_zkvm::entrypoint!(main);

use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, ProjectivePoint};

pub fn main() {
    #[allow(deprecated)]
    let g = <ProjectivePoint as k256::elliptic_curve::group::Group>::generator();
    #[allow(deprecated)]
    let id = <ProjectivePoint as k256::elliptic_curve::group::Group>::identity();

    // identity + generator = generator
    let r1 = id + g;
    assert_eq!(r1, g);
    sp1_zkvm::io::commit(&1u8);

    // generator + identity = generator
    let r2 = g + id;
    assert_eq!(r2, g);
    sp1_zkvm::io::commit(&2u8);

    // identity + identity = identity
    let r3 = id + id;
    assert_eq!(r3, id);
    sp1_zkvm::io::commit(&3u8);

    // generator - generator = identity
    let r4 = g - r2;
    assert_eq!(r4, id);
    sp1_zkvm::io::commit(&4u8);

    // identity.double() = identity
    let r5 = id.double();
    assert_eq!(r5, id);
    sp1_zkvm::io::commit(&5u8);

    // generator.double() = generator + generator
    let r6 = g.double();
    let r6b = g + g;
    assert_eq!(r6, r6b);
    sp1_zkvm::io::commit(&6u8);

    // Sum over empty iterator = identity
    let r7: ProjectivePoint = std::iter::empty::<ProjectivePoint>().sum();
    assert_eq!(r7, id);
    sp1_zkvm::io::commit(&7u8);

    // Sum over [generator] = generator
    let r8: ProjectivePoint = [g].into_iter().sum();
    assert_eq!(r8, g);
    sp1_zkvm::io::commit(&8u8);

    // AddAssign with identity
    let mut r9 = g;
    r9 += id;
    assert_eq!(r9, g);
    sp1_zkvm::io::commit(&9u8);

    // SubAssign: g -= g = identity
    let mut r10 = g;
    r10 -= g;
    assert_eq!(r10, id);
    sp1_zkvm::io::commit(&10u8);

    let mut compact = [0u8; 33];
    compact[0] = 0x05;
    compact[1..].copy_from_slice(&[
        0x2f, 0x8b, 0xde, 0x4d, 0x1a, 0x07, 0x20, 0x93, 0x55, 0xb4, 0xa7, 0x25, 0x0a, 0x5c, 0x51,
        0x28, 0xe8, 0x8b, 0x84, 0xbd, 0xdc, 0x61, 0x9a, 0xb7, 0xcb, 0xa8, 0xd5, 0x69, 0xb2, 0x40,
        0xef, 0xe4,
    ]);
    let encoded = k256::EncodedPoint::from_bytes(compact).unwrap();
    let point = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded)).unwrap();
    let uncompressed = point.to_encoded_point(false);
    assert_eq!(&uncompressed.as_bytes()[1..33], &compact[1..]);
    assert_eq!(
        &uncompressed.as_bytes()[33..],
        &[
            0xd8, 0xac, 0x22, 0x26, 0x36, 0xe5, 0xe3, 0xd6, 0xd4, 0xdb, 0xa9, 0xdd, 0xa6, 0xc9,
            0xc4, 0x26, 0xf7, 0x88, 0x27, 0x1b, 0xab, 0x0d, 0x68, 0x40, 0xdc, 0xa8, 0x7d, 0x3a,
            0xa6, 0xac, 0x62, 0xd6,
        ]
    );
}
