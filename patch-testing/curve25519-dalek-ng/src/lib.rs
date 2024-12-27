#[sp1_test::sp1_test("curve25519_ng_decompress", prove)]
fn test_decompressed_noncanonical(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use curve25519_dalek_ng::edwards::CompressedEdwardsY;
    use curve25519_dalek_ng::edwards::EdwardsPoint;
    use sp1_test::DEFAULT_CORPUS_COUNT;

    // non-canonical point
    let mut bytes: [u8; 32] = [0; 32];
    for i in 0..32 {
        bytes[i] = 255;
    }
    bytes[0] = 253;
    bytes[31] = 127;
    let compressed = CompressedEdwardsY(bytes);
    println!("{:?}", compressed.decompress());

    // y = 0 with sign off
    let mut bytes: [u8; 32] = [0; 32];
    let compressed = CompressedEdwardsY(bytes);
    println!("{:?}", compressed.decompress());

    // y = 0 with sign on
    let mut bytes: [u8; 32] = [0; 32];
    bytes[31] = 128;
    let compressed = CompressedEdwardsY(bytes);
    println!("{:?}", compressed.decompress());

    // x = 0 with sign off
    let mut bytes: [u8; 32] = [0; 32];
    bytes[0] = 1;
    let compressed = CompressedEdwardsY(bytes);
    println!("{:?}", compressed.decompress());

    // x = 0 with sign on
    let mut bytes: [u8; 32] = [0; 32];
    bytes[0] = 1;
    bytes[31] = 128;
    let compressed = CompressedEdwardsY(bytes);
    println!("{:?}", compressed.decompress());

    // x = 0 with sign off
    let mut bytes: [u8; 32] = [255u8; 32];
    bytes[0] = 255 - 19;
    bytes[31] = 127;
    let compressed = CompressedEdwardsY(bytes);
    println!("{:?}", compressed.decompress());

    // x = 0 with sign on
    let mut bytes: [u8; 32] = [255u8; 32];
    bytes[0] = 255 - 19;
    let compressed = CompressedEdwardsY(bytes);
    println!("{:?}", compressed.decompress());

    move |_| {}
}

#[sp1_test::sp1_test("curve25519_ng_add_then_multiply", prove)]
fn test_add_then_multiply(stdin: &mut sp1_sdk::SP1Stdin) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use curve25519_dalek_ng::edwards::CompressedEdwardsY;
    use curve25519_dalek_ng::edwards::EdwardsPoint;
    use sp1_test::DEFAULT_CORPUS_COUNT;

    let mut bytes1: [u8; 32] = [0; 32];
    for i in 0..32 {
        bytes1[i] = 3;
    }
    let mut bytes2: [u8; 32] = [0; 32];
    for i in 0..32 {
        bytes2[i] = 9;
    }

    let compressed1 = CompressedEdwardsY(bytes1);
    let point1 = compressed1.decompress().unwrap();
    let compressed2 = CompressedEdwardsY(bytes2);
    let point2 = compressed2.decompress().unwrap();

    let scalar = curve25519_dalek_ng::scalar::Scalar::from_bytes_mod_order([1u8; 32]);
    let point = point1 + point2;
    let result = point * scalar;
    println!("{:?}", result.compress());

    move |_| {}
}

#[sp1_test::sp1_test("curve25519_ng_zero_msm", prove)]
fn test_zero_msm(stdin: &mut sp1_sdk::SP1Stdin) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use curve25519_dalek_ng::edwards::CompressedEdwardsY;
    use curve25519_dalek_ng::edwards::EdwardsPoint;

    let mut bytes1: [u8; 32] = [0; 32];
    for i in 0..32 {
        bytes1[i] = 3;
    }
    let compressed1 = CompressedEdwardsY(bytes1);
    let point1 = compressed1.decompress().unwrap();

    let scalar1 = curve25519_dalek_ng::scalar::Scalar::from_bytes_mod_order([0u8; 32]);
    let scalar2 = curve25519_dalek_ng::scalar::Scalar::from_bytes_mod_order([0u8; 32]);
    let result = EdwardsPoint::vartime_double_scalar_mul_basepoint(&scalar1, &point1, &scalar2);
    println!("{:?}", result.compress());

    move |_| {}
}

#[sp1_test::sp1_test("curve25519_ng_zero_mul", prove)]
fn test_zero_mul(stdin: &mut sp1_sdk::SP1Stdin) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use curve25519_dalek_ng::edwards::CompressedEdwardsY;
    use curve25519_dalek_ng::edwards::EdwardsPoint;

    let mut bytes1: [u8; 32] = [0; 32];
    for i in 0..32 {
        bytes1[i] = 3;
    }
    let compressed1 = CompressedEdwardsY(bytes1);
    let point1 = compressed1.decompress().unwrap();

    let scalar1 = curve25519_dalek_ng::scalar::Scalar::from_bytes_mod_order([0u8; 32]);
    let result = point1 * &scalar1;
    println!("{:?}", result.compress());

    move |_| {}
}
