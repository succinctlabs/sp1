#[sp1_test::sp1_test("p256_verify", gpu, prove)]
pub fn test_verify_rand_lte_100(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};

    let times = 100_u8;
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

#[sp1_test::sp1_test("p256_recover", syscalls = [SECP256R1_ADD, SECP256R1_DOUBLE], gpu, prove)]
pub fn test_recover_rand_lte_100(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};

    let times = 100_u8;
    stdin.write(&(times as u16));

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
        for vkey in vkeys.into_iter() {
            let key = public.read::<Option<Vec<u8>>>();

            assert_eq!(key, Some(vkey.to_sec1_bytes().to_vec()));
        }
    }
}

#[sp1_test::sp1_test("p256_recover", syscalls = [SECP256R1_ADD, SECP256R1_DOUBLE])]
pub fn test_recover_high_hash_high_recid(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use ecdsa_core::RecoveryId;
    use p256::{ecdsa::Signature, ecdsa::VerifyingKey};

    let times = 100_u8;
    stdin.write(&times);

    let mut vkeys = Vec::with_capacity(times as usize);
    let cnt = 0;
    for idx in 0..times {
        let mut signature_bytes = [0u8; 64];
        for i in 16..64 {
            signature_bytes[i] = rand::random::<u8>();
        }
        let mut message = rand::random::<[u8; 32]>();
        for i in 0..4 {
            message[i] = 255;
        }
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

#[sp1_test::sp1_test("p256_recover", syscalls = [SECP256R1_ADD, SECP256R1_DOUBLE], gpu, prove)]
pub fn test_recover_pubkey_infinity(
    stdin: &mut sp1_sdk::SP1Stdin,
) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use ecdsa_core::RecoveryId;
    use p256::{ecdsa::Signature, ecdsa::VerifyingKey};

    let times = 3_u8;
    stdin.write(&times);

    let mut vkeys = Vec::with_capacity(times as usize);
    let msg1: [u8; 32] = [
        107, 23, 209, 242, 225, 44, 66, 71, 248, 188, 230, 229, 99, 164, 64, 242, 119, 3, 125, 129,
        45, 235, 51, 160, 244, 161, 57, 69, 216, 152, 194, 150,
    ];
    let r1: [u8; 32] = [
        107, 23, 209, 242, 225, 44, 66, 71, 248, 188, 230, 229, 99, 164, 64, 242, 119, 3, 125, 129,
        45, 235, 51, 160, 244, 161, 57, 69, 216, 152, 194, 150,
    ];
    let msg2: [u8; 32] = [
        249, 228, 246, 49, 26, 6, 158, 253, 20, 164, 112, 6, 9, 106, 53, 135, 129, 18, 211, 196,
        239, 228, 54, 107, 76, 22, 145, 248, 142, 205, 50, 240,
    ];
    let r2: [u8; 32] = [
        124, 242, 123, 24, 141, 3, 79, 126, 138, 82, 56, 3, 4, 181, 26, 195, 192, 137, 105, 226,
        119, 242, 27, 53, 166, 11, 72, 252, 71, 102, 153, 120,
    ];
    let msg3: [u8; 32] = [
        28, 99, 174, 117, 242, 153, 30, 205, 90, 231, 206, 191, 87, 227, 212, 49, 247, 109, 42,
        184, 39, 241, 94, 12, 254, 10, 103, 144, 88, 84, 210, 243,
    ];
    let r3: [u8; 32] = [
        94, 203, 228, 209, 166, 51, 10, 68, 200, 247, 239, 149, 29, 75, 241, 101, 230, 198, 183,
        33, 239, 173, 169, 133, 251, 65, 102, 27, 198, 231, 253, 108,
    ];

    for (idx, (msg, r)) in [(msg1, r1), (msg2, r2), (msg3, r3)].iter().enumerate() {
        let mut signature_bytes = [0u8; 64];
        signature_bytes[..32].copy_from_slice(r);
        signature_bytes[32..(32 + 32)].copy_from_slice(r);

        let recid = if idx == 2 { 0u8 } else { 1u8 };
        let recid = RecoveryId::from_byte(recid).unwrap();
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
