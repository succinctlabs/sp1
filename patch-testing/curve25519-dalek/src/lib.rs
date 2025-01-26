#[sp1_test::sp1_test("curve25519_decompress", syscalls = [ED_DECOMPRESS])]
fn test_decompressed_expected_value(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::edwards::EdwardsPoint;
    use rand::distributions::Distribution;
    use rand::distributions::WeightedIndex;
    use sp1_test::DEFAULT_CORPUS_COUNT;

    let dist = rand::distributions::WeightedIndex::new([9_usize, 1]).unwrap();

    /// Flips a bit in the compressed point with probability 0.1.
    ///
    /// Returns true if a bit was flipped. With probability .5 this is not a valid compressed point.
    fn bork_point(compressed: &mut CompressedEdwardsY, dist: &WeightedIndex<usize>) -> bool {
        if dist.sample(&mut rand::thread_rng()) == 1 {
            let bit = 1 << 2;
            compressed.0[0] ^= bit;

            return true;
        }

        false
    }

    let how_many_points = DEFAULT_CORPUS_COUNT as usize;
    stdin.write(&how_many_points);

    let mut decompress_outputs = Vec::new();
    while decompress_outputs.len() < how_many_points {
        let rand_scalar = curve25519_dalek::scalar::Scalar::random(&mut rand::thread_rng());
        let rand_point = EdwardsPoint::mul_base(&rand_scalar);
        let mut compressed = rand_point.compress();

        if bork_point(&mut compressed, &dist) {
            // if point has been borked lets just make it cant be decompressed.
            if compressed.decompress().is_some() {
                continue;
            }

            decompress_outputs.push(None);
        } else {
            decompress_outputs.push(compressed.decompress());
        }

        stdin.write(&compressed);
    }

    assert!(
        decompress_outputs.iter().any(|x| x.is_none()),
        "Expected at least one decompressed point to be None"
    );

    move |mut public| {
        for decompressed in decompress_outputs {
            assert_eq!(decompressed, public.read::<Option<EdwardsPoint>>());
        }
    }
}

#[sp1_test::sp1_test("curve25519_decompress")]
fn test_decompressed_noncanonical(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::edwards::EdwardsPoint;

    let how_many_points = 1_usize;
    stdin.write(&how_many_points);

    let mut decompress_outputs = Vec::new();
    while decompress_outputs.len() < how_many_points {
        let mut bytes: [u8; 32] = [0; 32];
        for i in 0..32 {
            bytes[i] = 255;
        }
        bytes[0] = 253;
        bytes[31] = 127;
        let compressed = CompressedEdwardsY(bytes);
        decompress_outputs.push(compressed.decompress());
        stdin.write(&compressed);
    }

    move |mut public| {
        for decompressed in decompress_outputs {
            let public_val = public.read::<Option<EdwardsPoint>>();
            assert!(public_val.is_none());
            assert!(decompressed.is_some());

            // assert_eq!(decompressed, public_val);
        }
    }
}

#[sp1_test::sp1_test("ed25519_verify", syscalls = [ED_ADD, ED_DECOMPRESS])]
fn test_ed25519_verify(stdin: &mut sp1_sdk::SP1Stdin) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use ed25519_dalek::Signer;

    let how_many_signatures = sp1_test::DEFAULT_CORPUS_COUNT as usize;
    stdin.write(&how_many_signatures);

    for _ in 0..how_many_signatures {
        let msg_len = rand::random::<usize>().min(1000);

        println!("Generating a message of length {}", msg_len);

        let msg = (0..msg_len).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());

        let sig = sk.sign(&msg);

        stdin.write(&(msg, sk.verifying_key(), sig));
    }

    move |mut public| {
        for _ in 0..how_many_signatures {
            assert!(public.read::<bool>());
        }
    }
}

#[sp1_test::sp1_test("curve25519_add_then_multiply", syscalls = [ED_ADD, ED_DECOMPRESS], prove)]
fn test_add_then_multiply(stdin: &mut sp1_sdk::SP1Stdin) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;

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

#[sp1_test::sp1_test("curve25519_zero_msm", syscalls = [ED_ADD, ED_DECOMPRESS], prove)]
fn test_zero_msm(_stdin: &mut sp1_sdk::SP1Stdin) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::edwards::EdwardsPoint;

    let bytes1: [u8; 32] = [3; 32];

    let compressed1 = CompressedEdwardsY(bytes1);
    let point1 = compressed1.decompress().unwrap();

    let scalar1 = curve25519_dalek::scalar::Scalar::from_bytes_mod_order([0u8; 32]);
    let scalar2 = curve25519_dalek::scalar::Scalar::from_bytes_mod_order([0u8; 32]);
    let result = EdwardsPoint::vartime_double_scalar_mul_basepoint(&scalar1, &point1, &scalar2);
    println!("{:?}", result.compress());

    move |_| {}
}

#[sp1_test::sp1_test("curve25519_zero_mul", syscalls = [ED_ADD, ED_DECOMPRESS], prove)]
fn test_zero_mul(_stdin: &mut sp1_sdk::SP1Stdin) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use curve25519_dalek::edwards::CompressedEdwardsY;

    let bytes1: [u8; 32] = [3; 32];

    let compressed1 = CompressedEdwardsY(bytes1);
    let point1 = compressed1.decompress().unwrap();

    let scalar1 = curve25519_dalek::scalar::Scalar::from_bytes_mod_order([0u8; 32]);
    let result = point1 * scalar1;
    println!("{:?}", result.compress());

    move |_| {}
}
