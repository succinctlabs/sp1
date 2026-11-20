#[cfg(test)]
mod tests {
    use secp256k1::{
        ecdsa::{RecoverableSignature, RecoveryId, Signature},
        Error, Message, PublicKey, Secp256k1, SecretKey,
    };

    fn high_s(compact: [u8; 64]) -> [u8; 64] {
        let mut high = compact;
        let order = secp256k1::constants::CURVE_ORDER;
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let value = order[i] as i16 - compact[32 + i] as i16 - borrow;
            high[32 + i] = value as u8;
            borrow = i16::from(value < 0);
        }
        assert_eq!(borrow, 0);
        high
    }

    fn high_s_vectors() -> Vec<(i32, [u8; 32], [u8; 64])> {
        let secp = Secp256k1::new();
        let mut vectors = Vec::new();
        for i in 1..=16u8 {
            let secret = SecretKey::from_slice(&[i; 32]).unwrap();
            let digest = [i.wrapping_mul(7); 32];
            let message = Message::from_digest_slice(&digest).unwrap();
            let (id, compact) = secp.sign_ecdsa_recoverable(&message, &secret).serialize_compact();
            vectors.push((id.to_i32(), digest, compact));
        }
        // Signing almost never produces IDs 2/3. Small r makes x = n + r
        // possible, so these fixtures exercise preservation of the X-reduced bit.
        for r in 1..=8u8 {
            let mut compact = [0; 64];
            compact[31] = r;
            compact[63] = 1;
            for id in 0..=3 {
                vectors.push((id, [0xab; 32], compact));
            }
        }
        // Exercise s = floor(n / 2) and its high-S partner immediately above
        // the boundary, with zero and unreduced (all-ones) message digests.
        let mut boundary = [0; 64];
        boundary[31] = 2;
        let mut carry = 0u8;
        for (i, byte) in secp256k1::constants::CURVE_ORDER.into_iter().enumerate() {
            boundary[32 + i] = (byte >> 1) | (carry << 7);
            carry = byte & 1;
        }
        for digest in [[0; 32], [255; 32]] {
            for id in 0..=3 {
                vectors.push((id, digest, boundary));
            }
        }
        vectors
    }

    #[sp1_test::sp1_test("secp256k1_recover_v0-29-1", syscalls = [SECP256K1_DOUBLE, SECP256K1_ADD], prove)]
    fn test_recover_high_s(stdin: &mut sp1_sdk::SP1Stdin) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
        recover_high_s(stdin, "029")
    }

    #[sp1_test::sp1_test("secp256k1_recover_v0-30-0", syscalls = [SECP256K1_DOUBLE, SECP256K1_ADD], prove)]
    fn test_recover_v0_30_0_high_s(
        stdin: &mut sp1_sdk::SP1Stdin,
    ) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
        recover_high_s(stdin, "030")
    }

    fn recover_high_s(
        stdin: &mut sp1_sdk::SP1Stdin,
        version: &str,
    ) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
        let secp = Secp256k1::new();
        let vectors = high_s_vectors();
        stdin.write(&u8::try_from(vectors.len() * 3).unwrap());
        let mut expected = Vec::new();
        let mut native_cases = Vec::new();
        let mut successful_ids = [0usize; 4];
        for (id, digest, compact) in vectors {
            let message = Message::from_digest_slice(&digest).unwrap();
            let low =
                RecoverableSignature::from_compact(&compact, RecoveryId::from_i32(id).unwrap())
                    .unwrap();
            let low_key = secp.recover_ecdsa(&message, &low).ok();
            successful_ids[id as usize] += usize::from(low_key.is_some());
            for (case_id, bytes) in
                [(id, compact), (id ^ 1, high_s(compact)), (id, high_s(compact))]
            {
                let sig = RecoverableSignature::from_compact(
                    &bytes,
                    RecoveryId::from_i32(case_id).unwrap(),
                )
                .unwrap();
                let key = secp.recover_ecdsa(&message, &sig).ok();
                if case_id == (id ^ 1) {
                    assert_eq!(key, low_key);
                }
                stdin.write(&case_id);
                stdin.write_vec(digest.to_vec());
                stdin.write_slice(&bytes);
                native_cases.push((case_id, digest, bytes.to_vec(), Vec::new()));
                expected.push(key);
            }
        }
        assert!(successful_ids.into_iter().all(|count| count > 0));
        let native_expected: Vec<_> = expected
            .iter()
            .map(|key| key.map(|key| key.serialize().to_vec()).ok_or(2)) // InvalidSignature
            .collect();
        check_native(version, "recover", &native_cases, &native_expected);
        move |mut public| {
            for key in expected {
                assert_eq!(public.read::<Option<PublicKey>>(), key);
            }
        }
    }

    #[sp1_test::sp1_test("secp256k1_verify_v0-29-1", syscalls = [SECP256K1_DOUBLE, SECP256K1_ADD], prove)]
    fn test_verify_high_s(stdin: &mut sp1_sdk::SP1Stdin) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
        verify_high_s(stdin, "029")
    }

    #[sp1_test::sp1_test("secp256k1_verify_v0-30-0", syscalls = [SECP256K1_DOUBLE, SECP256K1_ADD], prove)]
    fn test_verify_v0_30_0_high_s(
        stdin: &mut sp1_sdk::SP1Stdin,
    ) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
        verify_high_s(stdin, "030")
    }

    fn verify_high_s(
        stdin: &mut sp1_sdk::SP1Stdin,
        version: &str,
    ) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
        let secp = Secp256k1::new();
        let cases: Vec<_> = high_s_vectors()
            .into_iter()
            .filter_map(|(id, digest, compact)| {
                let message = Message::from_digest_slice(&digest).unwrap();
                let sig =
                    RecoverableSignature::from_compact(&compact, RecoveryId::from_i32(id).unwrap())
                        .unwrap();
                secp.recover_ecdsa(&message, &sig).ok().map(|key| (digest, compact, key))
            })
            .collect();
        let count = u8::try_from(cases.len() * 2).unwrap();
        let mut native_cases = Vec::new();
        let mut native_expected = Vec::new();
        stdin.write(&count);
        for (digest, compact, key) in cases {
            for (bytes, valid) in [(compact, true), (high_s(compact), false)] {
                let sig = Signature::from_compact(&bytes).unwrap();
                let message = Message::from_digest_slice(&digest).unwrap();
                assert_eq!(
                    secp.verify_ecdsa(&message, &sig, &key),
                    if valid { Ok(()) } else { Err(Error::IncorrectSignature) }
                );
                stdin.write_vec(digest.to_vec());
                stdin.write_vec(sig.serialize_der().to_vec());
                stdin.write(&key);
                native_cases.push((0, digest, bytes.to_vec(), key.serialize().to_vec()));
                native_expected.push(if valid { Ok(Vec::new()) } else { Err(1) });
            }
        }
        check_native(version, "verify", &native_cases, &native_expected);
        move |mut public| {
            for i in 0..count {
                assert_eq!(public.read::<bool>(), i % 2 == 0);
            }
        }
    }

    type NativeCase = (i32, [u8; 32], Vec<u8>, Vec<u8>);

    fn check_native(
        version: &str,
        operation: &str,
        cases: &[NativeCase],
        expected: &[Result<Vec<u8>, u8>],
    ) {
        use std::process::{Command, Stdio};
        let programs = match version {
            "029" => [env!("SECP_ORIGINAL_029"), env!("SECP_PATCHED_029")],
            "030" => [env!("SECP_ORIGINAL_030"), env!("SECP_PATCHED_030")],
            _ => unreachable!(),
        };
        for program in programs {
            let mut child = Command::new(program)
                .arg(operation)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            bincode::serialize_into(child.stdin.take().unwrap(), cases).unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(output.status.success(), "native reference failed {program}");
            let results: Vec<Result<Vec<u8>, u8>> = bincode::deserialize(&output.stdout).unwrap();
            assert_eq!(results, expected, "{program} {operation}");
        }
    }

    // Keep the nonzero component from a valid signature so that each case isolates
    // zero r, zero s, or both, without introducing another scalar-range error.
    fn zero_scalar_signatures(valid: [u8; 64]) -> [[u8; 64]; 3] {
        let mut zero_r = valid;
        zero_r[..32].fill(0);
        let mut zero_s = valid;
        zero_s[32..].fill(0);
        [zero_r, zero_s, [0; 64]]
    }

    #[sp1_test::sp1_test("secp256k1_verify_v0-29-1", syscalls = [SECP256K1_DOUBLE, SECP256K1_ADD], prove)]
    fn test_verify_zero_scalars(
        stdin: &mut sp1_sdk::SP1Stdin,
    ) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
        verify_zero_scalars(stdin, "029")
    }

    #[sp1_test::sp1_test("secp256k1_verify_v0-30-0", syscalls = [SECP256K1_DOUBLE, SECP256K1_ADD], prove)]
    fn test_verify_v0_30_0_zero_scalars(
        stdin: &mut sp1_sdk::SP1Stdin,
    ) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
        verify_zero_scalars(stdin, "030")
    }

    fn verify_zero_scalars(
        stdin: &mut sp1_sdk::SP1Stdin,
        version: &str,
    ) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[1; 32]).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret);
        let message = Message::from_digest_slice(&[0xab; 32]).unwrap();
        let valid = secp.sign_ecdsa(&message, &secret).serialize_compact();
        let invalid = zero_scalar_signatures(valid);
        let cases = [valid, invalid[0], invalid[1], invalid[2], valid];
        let expected = [true, false, false, false, true];
        let native_cases: Vec<_> = cases
            .iter()
            .map(|compact| (0, [0xab; 32], compact.to_vec(), public_key.serialize().to_vec()))
            .collect();
        // Preserve the exact API error, rather than reducing all errors to false.
        let native_expected: Vec<_> = expected
            .iter()
            .map(|valid| if *valid { Ok(Vec::new()) } else { Err(1) }) // IncorrectSignature
            .collect();
        check_native(version, "verify", &native_cases, &native_expected);
        stdin.write(&(cases.len() as u8));

        for (compact, should_verify) in cases.into_iter().zip(expected) {
            // Parsing must still accept zero scalars; verification must reject them.
            let signature = Signature::from_compact(&compact).unwrap();
            assert_eq!(
                secp.verify_ecdsa(&message, &signature, &public_key),
                if should_verify { Ok(()) } else { Err(Error::IncorrectSignature) },
            );
            stdin.write_vec(message.as_ref().to_vec());
            stdin.write_vec(signature.serialize_der().to_vec());
            stdin.write(&public_key);
        }

        move |mut public| {
            for should_verify in expected {
                assert_eq!(public.read::<bool>(), should_verify);
            }
        }
    }

    #[sp1_test::sp1_test("secp256k1_recover_v0-29-1", syscalls = [SECP256K1_DOUBLE, SECP256K1_ADD], prove)]
    fn test_recover_zero_scalars(
        stdin: &mut sp1_sdk::SP1Stdin,
    ) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
        recover_zero_scalars(stdin, "029")
    }

    #[sp1_test::sp1_test("secp256k1_recover_v0-30-0", syscalls = [SECP256K1_DOUBLE, SECP256K1_ADD], prove)]
    fn test_recover_v0_30_0_zero_scalars(
        stdin: &mut sp1_sdk::SP1Stdin,
    ) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
        recover_zero_scalars(stdin, "030")
    }

    fn recover_zero_scalars(
        stdin: &mut sp1_sdk::SP1Stdin,
        version: &str,
    ) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[1; 32]).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret);
        let message = Message::from_digest_slice(&[0xab; 32]).unwrap();
        let (valid_recid, valid) =
            secp.sign_ecdsa_recoverable(&message, &secret).serialize_compact();
        let mut cases = vec![(valid_recid.to_i32(), valid, Some(public_key))];
        for compact in zero_scalar_signatures(valid) {
            for recid in 0..=3 {
                cases.push((recid, compact, None));
            }
        }
        cases.push((valid_recid.to_i32(), valid, Some(public_key)));
        let native_cases: Vec<_> = cases
            .iter()
            .map(|(id, compact, _)| (*id, [0xab; 32], compact.to_vec(), Vec::new()))
            .collect();
        let native_expected: Vec<_> = cases
            .iter()
            .map(|(_, _, key)| key.map(|key| key.serialize().to_vec()).ok_or(2)) // InvalidSignature
            .collect();
        check_native(version, "recover", &native_cases, &native_expected);
        stdin.write(&(cases.len() as u8));

        for &(recid, compact, expected) in &cases {
            let signature =
                RecoverableSignature::from_compact(&compact, RecoveryId::from_i32(recid).unwrap())
                    .unwrap();
            assert_eq!(
                secp.recover_ecdsa(&message, &signature),
                expected.ok_or(Error::InvalidSignature),
            );
            stdin.write(&recid);
            stdin.write(message.as_ref());
            stdin.write_slice(&compact);
        }

        move |mut public| {
            for (_, _, expected) in cases {
                assert_eq!(public.read::<Option<PublicKey>>(), expected);
            }
        }
    }

    #[sp1_test::sp1_test("secp256k1_recover_v0-29-1", syscalls = [SECP256K1_DOUBLE, SECP256K1_ADD], prove)]
    fn test_recover_rand_lte_100(
        stdin: &mut sp1_sdk::SP1Stdin,
    ) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
        recover_rand_lte_100(stdin)
    }

    #[sp1_test::sp1_test("secp256k1_recover_v0-30-0", syscalls = [SECP256K1_DOUBLE, SECP256K1_ADD], prove)]
    fn test_recover_v0_30_0_rand_lte_100(
        stdin: &mut sp1_sdk::SP1Stdin,
    ) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
        recover_rand_lte_100(stdin)
    }

    fn recover_rand_lte_100(
        stdin: &mut sp1_sdk::SP1Stdin,
    ) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
        let times = 100_u8;

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
            println!("checking public values");
            for key in pubkeys {
                assert_eq!(public.read::<Option<PublicKey>>(), Some(key));
            }
        }
    }

    #[sp1_test::sp1_test("secp256k1_verify_v0-29-1", syscalls = [SECP256K1_DOUBLE, SECP256K1_ADD], prove)]
    fn test_verify_rand_lte_100(
        stdin: &mut sp1_sdk::SP1Stdin,
    ) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
        verify_rand_lte_100(stdin)
    }

    #[sp1_test::sp1_test("secp256k1_verify_v0-30-0", syscalls = [SECP256K1_DOUBLE, SECP256K1_ADD], prove)]
    fn test_verify_v0_30_0_rand_lte_100(
        stdin: &mut sp1_sdk::SP1Stdin,
    ) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
        verify_rand_lte_100(stdin)
    }

    fn verify_rand_lte_100(stdin: &mut sp1_sdk::SP1Stdin) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
        let times = 100_u8;
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
}
