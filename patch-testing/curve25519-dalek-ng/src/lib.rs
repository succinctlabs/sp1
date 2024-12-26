#[sp1_test::sp1_test("curve25519_ng_decompress", prove)]
fn test_decompressed_noncanonical(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use curve25519_dalek_ng::edwards::CompressedEdwardsY;
    use curve25519_dalek_ng::edwards::EdwardsPoint;
    use sp1_test::DEFAULT_CORPUS_COUNT;

    let mut bytes: [u8; 32] = [0; 32];
    for i in 0..32 {
        bytes[i] = 255;
    }
    bytes[0] = 253;
    bytes[31] = 127;
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
        bytes1[i] = 0;
    }
    let mut bytes2: [u8; 32] = [0; 32];
    for i in 0..32 {
        bytes2[i] = 9;
    }

    let compressed1 = CompressedEdwardsY(bytes1);
    println!("{:?}", compressed1.decompress());
    // let compressed2 = CompressedEdwardsY(bytes2);
    // println!("{:?}", compressed2.decompress());

    move |_| {}
}
