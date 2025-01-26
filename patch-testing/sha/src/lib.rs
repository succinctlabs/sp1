#[cfg(test)]
use sp1_sdk::SP1PublicValues;
use sp1_test::sp1_test;

#[sp1_test("sha2", syscalls = [SHA_COMPRESS, SHA_EXTEND], gpu, prove)]
fn test_sha2_expected_digest_lte_100_times(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(SP1PublicValues) {
    use sha2_v0_10_6::Digest as D2;
    use sha2_v0_9_8::Digest as D1;

    use sp1_test::DEFAULT_CORPUS_COUNT;
    use sp1_test::DEFAULT_CORPUS_MAX_LEN;

    let mut preimages =
        sp1_test::random_preimages_with_bounded_len(DEFAULT_CORPUS_COUNT, DEFAULT_CORPUS_MAX_LEN);

    sp1_test::add_hash_fn_edge_cases(&mut preimages);

    let digests = preimages
        .iter()
        .map(|preimage| {
            let mut sha256_9_8 = sha2_v0_9_8::Sha256::new();
            sha256_9_8.update(preimage);

            let mut sha256_10_6 = sha2_v0_10_6::Sha256::new();
            sha256_10_6.update(preimage);

            (sha256_9_8.finalize().into(), sha256_10_6.finalize().into())
        })
        .collect::<Vec<([u8; 32], [u8; 32])>>();

    // Write the number of preimages to the SP1Stdin
    // This should be equal to the number of digests.
    stdin.write(&preimages.len());
    preimages.iter().for_each(|preimage| stdin.write_slice(preimage.as_slice()));

    move |mut public| {
        for digest in digests {
            let committed = public.read::<([u8; 32], [u8; 32])>();

            assert_eq!(digest, committed);
        }
    }
}

#[sp1_test("sha3", syscalls = [SHA_COMPRESS, SHA_EXTEND], gpu, prove)]
fn test_sha3_expected_digest_lte_100_times(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(SP1PublicValues) {
    use sha3::Digest;
    use sha3::Sha3_256;

    use sp1_test::DEFAULT_CORPUS_COUNT;
    use sp1_test::DEFAULT_CORPUS_MAX_LEN;

    let mut preimages: Vec<Vec<u8>> =
        sp1_test::random_preimages_with_bounded_len(DEFAULT_CORPUS_COUNT, DEFAULT_CORPUS_MAX_LEN);

    sp1_test::add_hash_fn_edge_cases(&mut preimages);

    let digests = preimages
        .iter()
        .map(|preimage| {
            let mut sha3 = Sha3_256::new();
            sha3.update(preimage);

            sha3.finalize().into()
        })
        .collect::<Vec<[u8; 32]>>();

    // Write the number of preimages to the SP1Stdin
    // This should be equal to the number of digests.
    stdin.write(&preimages.len());
    preimages.iter().for_each(|preimage| stdin.write_slice(preimage.as_slice()));

    move |mut public| {
        for digest in digests {
            let committed = public.read::<[u8; 32]>();
            assert_eq!(digest, committed);
        }
    }
}
