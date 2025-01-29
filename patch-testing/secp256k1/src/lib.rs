#[cfg(test)]
use secp256k1::{Message, PublicKey, Secp256k1};

#[sp1_test::sp1_test("secp256k1_recover", syscalls = [SECP256K1_DOUBLE, SECP256K1_ADD])]
fn test_recover_rand_lte_100(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    let times = rand::random::<u8>().min(100);

    stdin.write(&times);

    let secp = Secp256k1::new();

    let mut pubkeys = Vec::with_capacity(times.into());
    for _ in 0..times {
        let mut rng = rand::thread_rng();
        let (secret, public) = secp.generate_keypair(&mut rng);

        pubkeys.push(public);

        let msg = rand::random::<[u8; 32]>();
        let msg = Message::from_digest_slice(&msg).unwrap();

        let signature = secp.sign_ecdsa_recoverable(&msg, &secret);

        // Verify that the unpatched version of this function recovers as expected.
        assert_eq!(secp.recover_ecdsa(&msg, &signature).unwrap(), public);

        let (recid, sig) = signature.serialize_compact();

        let recid = recid.to_i32();

        stdin.write(&recid);
        stdin.write(msg.as_ref());
        stdin.write_slice(sig.as_slice());
    }

    move |mut public| {
        println!("checking publioc values");
        for key in pubkeys {
            assert_eq!(public.read::<Option<PublicKey>>(), Some(key));
        }
    }
}

#[sp1_test::sp1_test("secp256k1_verify")]
fn test_verify_rand_lte_100(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    let times = rand::random::<u8>().min(100);
    stdin.write(&times);

    let secp = Secp256k1::new();

    for _ in 0..times {
        let mut rng = rand::thread_rng();
        let (secret, public) = secp.generate_keypair(&mut rng);

        let msg = rand::random::<[u8; 32]>();
        let msg = Message::from_digest_slice(&msg).unwrap();

        let signature = secp.sign_ecdsa(&msg, &secret);

        // verify the unpatched version of the function verifies as expected
        assert!(secp.verify_ecdsa(&msg, &signature, &public).is_ok());

        let msg = msg.as_ref().to_vec();
        let signature = signature.serialize_der().to_vec();

        stdin.write_vec(msg);
        stdin.write_vec(signature);
        stdin.write(&public);
    }

    move |mut public| {
        for _ in 0..times {
            assert!(public.read::<bool>());
        }
    }
}

// add cases for fail verify, although its not patched
