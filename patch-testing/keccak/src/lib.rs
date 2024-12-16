#[sp1_test::sp1_test("keccak_patch_test", gpu, prove)]
fn test_expected_digest_lte_100(stdin: &mut sp1_sdk::SP1Stdin) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use tiny_keccak::Hasher;

    let times = rand::random::<u8>();
    stdin.write(&times);
    
    let mut digests = Vec::with_capacity(times as usize);
    for _ in 0..times {
        let preimage = (0..rand::random::<u8>()).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
        
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
            let commited = public.read::<[u8; 32]>(); 

            assert_eq!(digest, commited);
        }
    }
}
