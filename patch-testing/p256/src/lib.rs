#[sp1_test::sp1_test("p256_verify", gpu, prove)]
pub fn test_verify_rand_lte_100(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};

    let times = rand::random::<u8>().min(100);
    stdin.write(&times);

    for _ in 0..times {
        let signing_key = SigningKey::random(&mut OsRng);
        let vkey = signing_key.verifying_key().to_sec1_bytes();

        let message = rand::random::<[u8; 32]>();
        let (sig, _) = signing_key.sign_recoverable(&message).unwrap();

        stdin.write(&(message.to_vec(), sig, vkey));
    }

    move |mut public| {
        for _ in 0..times {
            assert!(public.read::<bool>())
        }
    }
}

#[sp1_test::sp1_test("p256_recover", gpu, prove)]
pub fn test_recover_rand_lte_100(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};

    let times = rand::random::<u8>().min(100);
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

    move |mut public| {
        for (i, vkey) in vkeys.into_iter().enumerate() {
            let key = public.read::<Option<Vec<u8>>>();

            println!("{}: {:?}", i, vkey);

            assert_eq!(key, Some(vkey.to_sec1_bytes().to_vec()));
        }
    }
}
