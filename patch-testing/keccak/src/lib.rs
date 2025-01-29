#[sp1_test::sp1_test("keccak_patch_test", syscalls = [KECCAK_PERMUTE], gpu, prove)]
fn test_expected_digest_lte_100(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use tiny_keccak::Hasher;

    use sp1_test::random_preimages_with_bounded_len;
    use sp1_test::{DEFAULT_CORPUS_COUNT, DEFAULT_CORPUS_MAX_LEN};
    let mut preimages =
        random_preimages_with_bounded_len(DEFAULT_CORPUS_COUNT, DEFAULT_CORPUS_MAX_LEN);

    sp1_test::add_hash_fn_edge_cases(&mut preimages);

    let inputs_len = preimages.len();
    stdin.write(&inputs_len);

    let mut digests = Vec::with_capacity(inputs_len);
    for preimage in preimages {
        digests.push({
            let mut output = [0u8; 32];
            let mut hasher = tiny_keccak::Keccak::v256();
            hasher.update(&preimage);
            hasher.finalize(&mut output);
            output
        });

        stdin.write_vec(preimage);
    }

    move |mut public| {
        for digest in digests {
            let committed = public.read::<[u8; 32]>();

            assert_eq!(digest, committed);
        }
    }
}
