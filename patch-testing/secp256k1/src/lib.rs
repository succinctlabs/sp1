#[cfg(test)]
use secp256k1::{Secp256k1, PublicKey, Message};

#[test]
fn test_recover_rand_lte_100() {
    const ELF: &[u8] = sp1_sdk::include_elf!("secp256k1_recover");

    let times = rand::random::<u8>().min(100);

    let secp = Secp256k1::new();
    let mut stdin = sp1_sdk::SP1Stdin::new();
    stdin.write(&times);
    
    let mut pubkeys = Vec::with_capacity(times.into());
    for _ in 0..times {
        let mut rng = rand::thread_rng();
        let (secret, public) = secp.generate_keypair(&mut rng);

        pubkeys.push(public);

        let msg = rand::random::<[u8; 32]>();
        let msg = Message::from_digest_slice(&msg).unwrap();

        let signature = secp.sign_ecdsa_recoverable(&msg, &secret);

        let (recid, sig) = signature.serialize_compact();

        let recid = recid.to_i32();

        stdin.write(&recid);
        stdin.write(msg.as_ref());
        stdin.write_slice(sig.as_slice());
    }

    let client = sp1_sdk::ProverClient::new();
    let (mut commited, _) = client.execute(ELF, stdin).run().unwrap();

    for key in pubkeys {
        assert_eq!(commited.read::<Option<PublicKey>>(), Some(key));
    }
}

#[test]
fn test_verify_rand_lte_100() {
    const ELF: &[u8] = sp1_sdk::include_elf!("secp256k1_verify");

    let times = rand::random::<u8>().min(100);

    let secp = Secp256k1::new();
    let mut stdin = sp1_sdk::SP1Stdin::new();
    stdin.write(&times);

    for _ in 0..times {
        let mut rng = rand::thread_rng();
        let (secret, public) = secp.generate_keypair(&mut rng);

        let msg = rand::random::<[u8; 32]>();
        let msg = Message::from_digest_slice(&msg).unwrap();

        let signature = secp.sign_ecdsa(&msg, &secret);

        let msg = msg.as_ref().to_vec();
        let signature = signature.serialize_der().to_vec();
        
        stdin.write_vec(msg);
        stdin.write_vec(signature);
        stdin.write(&public);
    }

    let client = sp1_sdk::ProverClient::new();
    let (mut commited, _) = client.execute(ELF, stdin).run().unwrap();

    for _ in 0..times {
        assert!(commited.read::<bool>());
    }
}
