#[cfg(test)]
#[path = "../program/xof_cases.rs"]
mod xof_cases;

#[cfg(test)]
mod patched_xof_cases {
    use sha3_patched as sha3;
    include!("../program/xof_cases.rs");
}

#[cfg(test)]
mod tests {
    use sha2::Digest;
    use sp1_sdk::SP1PublicValues;
    use sp1_test::sp1_test;

    fn assert_xof_outputs(actual: Vec<Vec<u8>>, expected: &[Vec<u8>]) {
        assert_eq!(actual.len(), expected.len());
        for (index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
            assert_eq!(actual, expected, "XOF case {index}");
        }
    }

    #[sp1_test("keccak256", syscalls = [KECCAK_PERMUTE], gpu, prove)]
    fn test_keccak256_precompile(stdin: &mut sp1_sdk::SP1Stdin) -> impl FnOnce(SP1PublicValues) {
        use sha3::Digest;

        let lengths = [0, 1, 135, 136, 137, 271, 272, 273, 1024];
        stdin.write(&lengths.len());
        let expected: Vec<[u8; 32]> = lengths
            .into_iter()
            .map(|len| {
                let input: Vec<u8> = (0..len).map(|i| i as u8).collect();
                let original: [u8; 32] = sha3::Keccak256::digest(&input).into();
                let patched: [u8; 32] = sha3_patched::Keccak256::digest(&input).into();
                assert_eq!(patched, original);
                stdin.write_slice(&input);
                original
            })
            .collect();
        move |mut public| {
            for digest in expected {
                assert_eq!(public.read::<[u8; 32]>(), digest);
            }
        }
    }

    #[sp1_test("turbo_shake", gpu, prove)]
    fn test_turbo_shake_boundaries(_: &mut sp1_sdk::SP1Stdin) -> impl FnOnce(SP1PublicValues) {
        let expected = super::xof_cases::turbo_shake_cases();
        assert_eq!(expected.len(), 576);
        assert_xof_outputs(super::patched_xof_cases::turbo_shake_cases(), &expected);
        move |mut public| assert_xof_outputs(public.read::<Vec<Vec<u8>>>(), &expected)
    }

    #[sp1_test("shake_xof", syscalls = [KECCAK_PERMUTE], gpu, prove)]
    fn test_shake_xof_boundaries(_: &mut sp1_sdk::SP1Stdin) -> impl FnOnce(SP1PublicValues) {
        let expected = super::xof_cases::shake_cases();
        assert_eq!(expected.len(), 144);
        assert_xof_outputs(super::patched_xof_cases::shake_cases(), &expected);
        move |mut public| assert_xof_outputs(public.read::<Vec<Vec<u8>>>(), &expected)
    }

    #[sp1_test("sha2_v0_9_9", syscalls = [SHA_COMPRESS, SHA_EXTEND], gpu, prove)]
    fn test_sha2_v0_9_9_expected_digest_lte_100_times(
        stdin: &mut sp1_sdk::SP1Stdin,
    ) -> impl FnOnce(SP1PublicValues) {
        sha2_expected_digest_lte_100_times(stdin)
    }

    #[sp1_test("sha2_v0_10_6", syscalls = [SHA_COMPRESS, SHA_EXTEND], gpu, prove)]
    fn test_sha2_v0_10_6_expected_digest_lte_100_times(
        stdin: &mut sp1_sdk::SP1Stdin,
    ) -> impl FnOnce(SP1PublicValues) {
        sha2_expected_digest_lte_100_times(stdin)
    }

    #[sp1_test("sha2_v0_10_8", syscalls = [SHA_COMPRESS, SHA_EXTEND], gpu, prove)]
    fn test_sha2_v0_10_8_expected_digest_lte_100_times(
        stdin: &mut sp1_sdk::SP1Stdin,
    ) -> impl FnOnce(SP1PublicValues) {
        sha2_expected_digest_lte_100_times(stdin)
    }

    #[sp1_test("sha2_v0_10_9", syscalls = [SHA_COMPRESS, SHA_EXTEND], gpu, prove)]
    fn test_sha2_v0_10_9_expected_digest_lte_100_times(
        stdin: &mut sp1_sdk::SP1Stdin,
    ) -> impl FnOnce(SP1PublicValues) {
        sha2_expected_digest_lte_100_times(stdin)
    }

    #[sp1_test("sha2_v0_11_0", syscalls = [SHA_COMPRESS, SHA_EXTEND], gpu, prove)]
    fn test_sha2_v0_11_0_expected_digest_lte_100_times(
        stdin: &mut sp1_sdk::SP1Stdin,
    ) -> impl FnOnce(SP1PublicValues) {
        sha2_expected_digest_lte_100_times(stdin)
    }

    fn sha2_expected_digest_lte_100_times(
        stdin: &mut sp1_sdk::SP1Stdin,
    ) -> impl FnOnce(SP1PublicValues) {
        use sp1_test::DEFAULT_CORPUS_COUNT;
        use sp1_test::DEFAULT_CORPUS_MAX_LEN;

        let mut preimages = sp1_test::random_preimages_with_bounded_len(
            DEFAULT_CORPUS_COUNT,
            DEFAULT_CORPUS_MAX_LEN,
        );

        sp1_test::add_hash_fn_edge_cases(&mut preimages);

        let digests = preimages
            .iter()
            .map(|preimage| {
                let mut sha256 = sha2::Sha256::new();
                sha256.update(preimage);

                sha256.finalize().into()
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

    #[sp1_test("sha3", syscalls = [KECCAK_PERMUTE], gpu, prove)]
    fn test_sha3_expected_digest_lte_100_times(
        stdin: &mut sp1_sdk::SP1Stdin,
    ) -> impl FnOnce(SP1PublicValues) {
        use sha3::Digest;
        use sha3::Sha3_256;

        use sp1_test::DEFAULT_CORPUS_COUNT;
        use sp1_test::DEFAULT_CORPUS_MAX_LEN;

        let mut preimages: Vec<Vec<u8>> = sp1_test::random_preimages_with_bounded_len(
            DEFAULT_CORPUS_COUNT,
            DEFAULT_CORPUS_MAX_LEN,
        );

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
}
