#[sp1_test::sp1_test("curve25519_ng_decompress", syscalls = [ED_DECOMPRESS], prove)]
fn test_decompressed_noncanonical(
    _stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use curve25519_dalek_ng::edwards::CompressedEdwardsY;

    // non-canonical point
    let mut bytes: [u8; 32] = [255; 32];
    bytes[0] = 253;
    bytes[31] = 127;
    let compressed = CompressedEdwardsY(bytes);
    println!("{:?}", compressed.decompress());

    // y = 0 with sign off
    let bytes: [u8; 32] = [0; 32];
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

#[sp1_test::sp1_test("curve25519_ng_add_then_multiply", syscalls = [ED_ADD, ED_DECOMPRESS], prove)]
fn test_add_then_multiply(stdin: &mut sp1_sdk::SP1Stdin) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use curve25519_dalek_ng::edwards::CompressedEdwardsY;
    use curve25519_dalek_ng::scalar::Scalar;

    let times = 100u16;
    stdin.write(&{ times });

    let mut result_vec = Vec::with_capacity(times as usize);

    for _ in 0..times {
        let bytes1 = rand::random::<[u8; 32]>();
        let bytes2 = rand::random::<[u8; 32]>();
        let scalar = rand::random::<[u8; 32]>();
        stdin.write(&bytes1);
        stdin.write(&bytes2);
        stdin.write(&scalar);

        let compressed1 = CompressedEdwardsY(bytes1);
        let point1 = compressed1.decompress();
        let compressed2 = CompressedEdwardsY(bytes2);
        let point2 = compressed2.decompress();

        if point1.is_some() && point2.is_some() {
            let point = point1.unwrap() + point2.unwrap();
            let scalar = Scalar::from_bytes_mod_order(scalar);
            let result = point * scalar;
            result_vec.push(result.compress().to_bytes());
        } else {
            result_vec.push(compressed1.to_bytes());
        }
    }

    move |mut public| {
        for expected_result in result_vec.into_iter() {
            let patch_result = public.read::<[u8; 32]>();

            assert_eq!(patch_result, expected_result);
        }
    }
}

#[sp1_test::sp1_test("curve25519_ng_zero_msm", syscalls = [ED_ADD, ED_DECOMPRESS], prove)]
fn test_zero_msm(_stdin: &mut sp1_sdk::SP1Stdin) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use curve25519_dalek_ng::edwards::CompressedEdwardsY;
    use curve25519_dalek_ng::edwards::EdwardsPoint;

    let bytes1: [u8; 32] = [3; 32];

    let compressed1 = CompressedEdwardsY(bytes1);
    let point1 = compressed1.decompress().unwrap();

    let scalar1 = curve25519_dalek_ng::scalar::Scalar::from_bytes_mod_order([0u8; 32]);
    let scalar2 = curve25519_dalek_ng::scalar::Scalar::from_bytes_mod_order([0u8; 32]);
    let result = EdwardsPoint::vartime_double_scalar_mul_basepoint(&scalar1, &point1, &scalar2);
    println!("{:?}", result.compress());

    move |_| {}
}

#[sp1_test::sp1_test("curve25519_ng_zero_mul", syscalls = [ED_ADD, ED_DECOMPRESS], prove)]
fn test_zero_mul(_stdin: &mut sp1_sdk::SP1Stdin) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use curve25519_dalek_ng::edwards::CompressedEdwardsY;

    let bytes1: [u8; 32] = [3; 32];
    let compressed1 = CompressedEdwardsY(bytes1);
    let point1 = compressed1.decompress().unwrap();

    let scalar1 = curve25519_dalek_ng::scalar::Scalar::from_bytes_mod_order([0u8; 32]);
    let result = point1 * scalar1;
    println!("{:?}", result.compress());

    move |_| {}
}
