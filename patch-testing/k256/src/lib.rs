#[test]
pub fn test_verify_rand_lte_100() {
    use k256::{
        ecdsa::SigningKey,
        elliptic_curve::rand_core::OsRng,
    };

    let times = rand::random::<u8>().min(100);
    let mut stdin = sp1_sdk::SP1Stdin::new();
    stdin.write(&times);

    for _ in 0..times {
        let signing_key = SigningKey::random(&mut OsRng);
        let vkey = signing_key.verifying_key().to_sec1_bytes();

        let message = rand::random::<[u8; 32]>();
        let (sig, _) = signing_key.sign_recoverable(&message).unwrap();
        
        stdin.write(&(message.to_vec(), sig, vkey));
    }

    const ELF: &[u8] = sp1_sdk::include_elf!("k256_verify");
    let prover = sp1_sdk::ProverClient::new();

    let (mut public, _) = prover.execute(ELF, stdin).run().unwrap();
    
    for _ in 0..times {
        assert!(public.read::<bool>())
    }
}

#[test]
pub fn test_recover_rand_lte_100() {
    use k256::{
        ecdsa::SigningKey,
        elliptic_curve::rand_core::OsRng,
    };

    let times = rand::random::<u8>().min(100);
    let mut stdin = sp1_sdk::SP1Stdin::new();
    stdin.write(&times);
    
    let mut vkeys = Vec::with_capacity(times as usize);
    for _ in 0..times {
        let signing_key = SigningKey::random(&mut OsRng);
        let vkey = *signing_key.verifying_key();
        vkeys.push(vkey);

        let message = rand::random::<[u8; 32]>();
        let (sig, recid) = signing_key.sign_prehash_recoverable(&message).unwrap();
 
        stdin.write(&(message.to_vec(), sig, recid.to_byte()));
    }

    const ELF: &[u8] = sp1_sdk::include_elf!("k256_recover");
    let prover = sp1_sdk::ProverClient::new();

    let (mut public, _) = prover.execute(ELF, stdin).run().unwrap();
    
    for (i, vkey) in vkeys.into_iter().enumerate() {
        let key = public.read::<Option<Vec<u8>>>();

        println!("{}: {:?}", i, vkey);
        
        assert_eq!(key, Some(vkey.to_sec1_bytes().to_vec()));
    }
}
