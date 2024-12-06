    #[test]
    fn test_ed25519_dalek() {
        const PATCH_TEST_ELF: &[u8] = sp1_sdk::include_elf!("ed25519-dalek");
        let mut stdin = sp1_sdk::SP1Stdin::new();

        let client = sp1_sdk::ProverClient::new();
        let (_, _) = client.execute(PATCH_TEST_ELF, stdin).run().expect("executing failed");
    }
    #[test]
    fn test_curve25519_dalek_ng() {
        const PATCH_TEST_ELF: &[u8] = sp1_sdk::include_elf!("curve25519-dalek-ng");
        let mut stdin = sp1_sdk::SP1Stdin::new();

        let client = sp1_sdk::ProverClient::new();
        let (_, _) = client.execute(PATCH_TEST_ELF, stdin).run().expect("executing failed");
    }
    #[test]
    fn test_ed25519_consensus() {
        const PATCH_TEST_ELF: &[u8] = sp1_sdk::include_elf!("ed25519-consensus");
        let mut stdin = sp1_sdk::SP1Stdin::new();

        let client = sp1_sdk::ProverClient::new();
        let (_, _) = client.execute(PATCH_TEST_ELF, stdin).run().expect("executing failed");
    }
    #[test]
    fn test_k256() {
        const PATCH_TEST_ELF: &[u8] = sp1_sdk::include_elf!("k256");
        let mut stdin = sp1_sdk::SP1Stdin::new();

        let client = sp1_sdk::ProverClient::new();
        let (_, _) = client.execute(PATCH_TEST_ELF, stdin).run().expect("executing failed");
    }
    #[test]
    fn test_keccack() {
        const PATCH_TEST_ELF: &[u8] = sp1_sdk::include_elf!("keccack");
        let mut stdin = sp1_sdk::SP1Stdin::new();

        let client = sp1_sdk::ProverClient::new();
        let (_, _) = client.execute(PATCH_TEST_ELF, stdin).run().expect("executing failed");
    }
    #[test]
    fn test_p256() {
        const PATCH_TEST_ELF: &[u8] = sp1_sdk::include_elf!("p256");
        let mut stdin = sp1_sdk::SP1Stdin::new();

        let client = sp1_sdk::ProverClient::new();
        let (_, _) = client.execute(PATCH_TEST_ELF, stdin).run().expect("executing failed");
    }
    #[test]
    fn test_secp256k1() {
        const PATCH_TEST_ELF: &[u8] = sp1_sdk::include_elf!("secp256k1");
        let mut stdin = sp1_sdk::SP1Stdin::new();

        let client = sp1_sdk::ProverClient::new();
        let (_, _) = client.execute(PATCH_TEST_ELF, stdin).run().expect("executing failed");
    }
    #[test]
    fn test_sha() {
        const PATCH_TEST_ELF: &[u8] = sp1_sdk::include_elf!("sha");
        let mut stdin = sp1_sdk::SP1Stdin::new();

        let client = sp1_sdk::ProverClient::new();
        let (_, _) = client.execute(PATCH_TEST_ELF, stdin).run().expect("executing failed");
    }
