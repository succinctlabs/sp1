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
