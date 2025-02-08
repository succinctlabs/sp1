use ecdsa_core::signature::SignerMut;

#[sp1_test::sp1_test("k256_verify", gpu, prove)]
pub fn test_verify_rand_lte_100(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use k256::{
        ecdsa::{signature::Verifier, SigningKey},
        elliptic_curve::rand_core::OsRng,
    };

    let times = 100_u8;
    stdin.write(&times);

    for _ in 0..times {
        let signing_key = SigningKey::random(&mut OsRng);
        let vkey = signing_key.verifying_key();

        let message = rand::random::<[u8; 32]>();
        let (sig, _) = signing_key.sign_recoverable(&message).unwrap();

        assert!(vkey.verify(&message, &sig).is_ok());

        stdin.write(&(message.to_vec(), sig, vkey.to_sec1_bytes()));
    }

    move |mut public| {
        for _ in 0..times {
            assert!(public.read::<bool>())
        }
    }
}

#[sp1_test::sp1_test("k256_recover", syscalls = [SECP256K1_ADD, SECP256K1_DOUBLE], gpu, prove)]
pub fn test_recover_rand_lte_100(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use k256::{
        ecdsa::{SigningKey, VerifyingKey},
        elliptic_curve::rand_core::OsRng,
    };

    let times = 100_u8;
    stdin.write(&(times as u16));

    let mut vkeys = Vec::with_capacity(times as usize);
    for _ in 0..times {
        let signing_key = SigningKey::random(&mut OsRng);
        let vkey = *signing_key.verifying_key();
        vkeys.push(vkey);

        let message = rand::random::<[u8; 32]>();
        let (sig, recid) = signing_key.sign_prehash_recoverable(&message).unwrap();

        assert_eq!(vkey, VerifyingKey::recover_from_prehash(&message, &sig, recid).unwrap());

        stdin.write(&(message.to_vec(), sig, recid.to_byte()));
    }

    move |mut public| {
        for vkey in vkeys.into_iter() {
            let key = public.read::<Option<Vec<u8>>>();

            assert_eq!(key, Some(vkey.to_sec1_bytes().to_vec()));
        }
    }
}

#[sp1_test::sp1_test("k256_recover", syscalls = [SECP256K1_ADD, SECP256K1_DOUBLE])]
pub fn test_recover_high_hash_high_recid(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use ecdsa_core::RecoveryId;
    use k256::{ecdsa::Signature, ecdsa::VerifyingKey};

    let times = 100_u8;
    stdin.write(&times);

    let mut vkeys = Vec::with_capacity(times as usize);
    let cnt = 0;
    for idx in 0..times {
        let mut signature_bytes = [0u8; 64];
        for i in 16..64 {
            signature_bytes[i] = rand::random::<u8>();
        }
        signature_bytes[15] = rand::random::<u8>() % 2;
        let mut message = rand::random::<[u8; 32]>();
        for i in 0..15 {
            message[i] = 255;
        }
        message[15] = 254;
        let recid_byte = rand::random::<u8>() % 4;
        if recid_byte < 2 {
            for i in 0..16 {
                signature_bytes[i] = rand::random::<u8>();
            }
        }
        let recid = RecoveryId::from_byte(recid_byte).unwrap();
        let signature = Signature::from_slice(&signature_bytes).unwrap();

        let recovered_key = VerifyingKey::recover_from_prehash(&message, &signature, recid);

        stdin.write(&(message.to_vec(), signature, recid.to_byte()));
        vkeys.push(recovered_key.ok().map(|vk| vk.to_sec1_bytes().to_vec()));
    }

    move |mut public| {
        let mut fail_count = 0;
        for (i, vkey) in vkeys.into_iter().enumerate() {
            let key = public.read::<Option<Vec<u8>>>();

            assert_eq!(key, vkey);

            if key.is_none() {
                fail_count += 1;
            }
        }

        println!("fail {} / 100", fail_count);
    }
}

#[sp1_test::sp1_test("k256_recover", syscalls = [SECP256K1_ADD, SECP256K1_DOUBLE], gpu, prove)]
pub fn test_recover_pubkey_infinity(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use ecdsa_core::RecoveryId;
    use k256::{ecdsa::Signature, ecdsa::VerifyingKey};

    let times = 3_u8;
    stdin.write(&times);

    let mut vkeys = Vec::with_capacity(times as usize);
    let msg1: [u8; 32] = [
        121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7, 2, 155, 252,
        219, 45, 206, 40, 217, 89, 242, 129, 91, 22, 248, 23, 152,
    ];

    let r1: [u8; 32] = [
        121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7, 2, 155, 252,
        219, 45, 206, 40, 217, 89, 242, 129, 91, 22, 248, 23, 152,
    ];
    let msg2: [u8; 32] = [
        140, 8, 255, 40, 131, 218, 250, 218, 96, 138, 128, 221, 43, 128, 249, 177, 254, 64, 63,
        176, 106, 149, 217, 19, 151, 133, 180, 229, 232, 170, 252, 137,
    ];

    let r2: [u8; 32] = [
        198, 4, 127, 148, 65, 237, 125, 109, 48, 69, 64, 110, 149, 192, 124, 216, 92, 119, 142, 75,
        140, 239, 60, 167, 171, 172, 9, 185, 92, 112, 158, 229,
    ];

    let msg3: [u8; 32] = [
        235, 145, 158, 4, 183, 10, 73, 48, 219, 156, 238, 145, 233, 215, 246, 127, 170, 55, 159, 3,
        43, 189, 140, 154, 18, 97, 22, 33, 150, 52, 34, 105,
    ];

    let r3: [u8; 32] = [
        249, 48, 138, 1, 146, 88, 195, 16, 73, 52, 79, 133, 248, 157, 82, 41, 181, 49, 200, 69,
        131, 111, 153, 176, 134, 1, 241, 19, 188, 224, 54, 249,
    ];

    for (msg, r) in [(msg1, r1), (msg2, r2), (msg3, r3)].iter() {
        let mut signature_bytes = [0u8; 64];
        signature_bytes[..32].copy_from_slice(r);
        signature_bytes[32..(32 + 32)].copy_from_slice(r);
        let recid = RecoveryId::from_byte(0u8).unwrap();
        let signature = Signature::from_slice(&signature_bytes).unwrap();
        let recovered_key = VerifyingKey::recover_from_prehash(msg, &signature, recid);
        stdin.write(&(msg.to_vec(), signature, recid.to_byte()));
        vkeys.push(recovered_key.ok().map(|vk| vk.to_sec1_bytes().to_vec()));
    }
    move |mut public| {
        for vkey in vkeys.into_iter() {
            let key = public.read::<Option<Vec<u8>>>();
            assert_eq!(key, vkey);
            assert!(key.is_none());
            assert!(vkey.is_none());
        }
    }
}

#[sp1_test::sp1_test("k256_schnorr_verify", gpu, prove)]
pub fn test_schnorr_verify(stdin: &mut sp1_sdk::SP1Stdin) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use k256::{
        elliptic_curve::rand_core::OsRng,
        schnorr::{
            signature::{SignerMut, Verifier},
            SigningKey,
        },
    };

    let times = 100_u8;
    stdin.write(&times);

    for _ in 0..times {
        let mut signing_key = SigningKey::random(&mut OsRng);

        let message = rand::random::<[u8; 32]>();
        let sig = signing_key.sign(&message);
        let vkey = signing_key.verifying_key();

        assert!(vkey.verify(&message, &sig).is_ok());

        stdin.write(&message);
        stdin.write_slice(sig.to_bytes().as_slice());
        stdin.write_slice(vkey.to_bytes().as_slice());
    }

    move |mut public| {
        for _ in 0..times {
            assert!(public.read::<bool>())
        }
    }
}
