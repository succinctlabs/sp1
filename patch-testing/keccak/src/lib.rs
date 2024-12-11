#[test]
fn test_expected_digest_lte_100() {
    use tiny_keccak::Hasher;

    let times = rand::random::<u8>();
    let mut stdin = sp1_sdk::SP1Stdin::new();
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

    const ELF: &[u8] = sp1_sdk::include_elf!("keccak_patch_test");
    let client = sp1_sdk::ProverClient::new();

    let (mut public, _) = client.execute(ELF, stdin).run().unwrap();

    for digest in digests {
        let commited = public.read::<[u8; 32]>(); 

        assert_eq!(digest, commited);
    }
}
