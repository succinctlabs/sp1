#[sp1_test::sp1_test("curve25519_ng_encoding", syscalls = [ED_DECOMPRESS], prove)]
fn test_decompressed_noncanonical(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use curve25519_dalek_ng::edwards::CompressedEdwardsY;

    let mut inputs = Vec::new();
    for noncanonical in [false, true] {
        for offset in 0..19u8 {
            for sign in [0u8, 0x80] {
                let mut bytes = if noncanonical { [255; 32] } else { [0; 32] };
                bytes[0] = if noncanonical { 237 + offset } else { offset };
                bytes[31] = if noncanonical { 0x7f | sign } else { sign };
                inputs.push(bytes);
            }
        }
    }
    // Include the upper canonical boundary and both signs of its zero X.
    for sign in [0u8, 0x80] {
        let mut bytes = [255; 32];
        bytes[0] = 236;
        bytes[31] = 0x7f | sign;
        inputs.push(bytes);
    }
    let expected: Vec<_> = inputs
        .iter()
        .map(|bytes| {
            CompressedEdwardsY(*bytes)
                .decompress()
                .map(|point| point.compress().to_bytes())
        })
        .collect();
    let native_patched: Vec<_> = inputs
        .iter()
        .map(|bytes| {
            curve25519_dalek_ng_patched::edwards::CompressedEdwardsY(*bytes)
                .decompress()
                .map(|point| point.compress().to_bytes())
        })
        .collect();
    assert_eq!(native_patched, expected);
    assert_eq!(
        expected[38..76]
            .iter()
            .filter(|point| point.is_some())
            .count(),
        24
    );
    assert_eq!(&expected[..38], &expected[38..76]);
    stdin.write(&inputs);
    move |mut public| {
        for point in expected {
            assert_eq!(public.read::<Option<[u8; 32]>>(), point);
        }
    }
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
