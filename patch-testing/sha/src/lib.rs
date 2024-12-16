use sha2_v0_10_6::Digest as D2;

use sha2_v0_9_8::Digest as D1;

use sp1_sdk::SP1PublicValues;

use sp1_test::sp1_test;

#[sp1_test("sha_256_program", gpu, prove)]
fn test_expected_digest_rand_times_lte_100_test(stdin: &mut sp1_sdk::SP1Stdin) -> impl FnOnce(SP1PublicValues) {
    let times = rand::random::<u8>().min(100);

    let preimages: Vec<Vec<u8>> = (0..times)
        .map(|_| {
            let rand_len = rand::random::<u8>();
            (0..rand_len).map(|_| rand::random::<u8>()).collect::<Vec<u8>>()
        })
        .collect();

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

    stdin.write(&times);
    preimages.iter().for_each(|preimage| stdin.write_slice(preimage.as_slice()));

    move |mut public| {
        let outputs = public.read::<Vec<([u8; 32], [u8; 32])>>();
        assert_eq!(digests, outputs);
    }
}
