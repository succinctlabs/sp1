#[cfg(test)]
mod cases;

#[sp1_test::sp1_test("ed25519_consensus_zip215", syscalls = [ED_ADD, ED_DECOMPRESS], prove)]
fn test_zip215_encodings(stdin: &mut sp1_sdk::SP1Stdin) -> impl FnOnce(sp1_sdk::SP1PublicValues) {
    use ed25519_consensus::VerificationKey;
    let encodings = cases::encodings();
    let keys: Vec<_> = encodings
        .iter()
        .map(|bytes| VerificationKey::try_from(*bytes).ok().map(|key| key.to_bytes()))
        .collect();
    let patched_keys: Vec<_> = encodings
        .iter()
        .map(|bytes| {
            ed25519_consensus_patched::VerificationKey::try_from(*bytes)
                .ok()
                .map(|key| key.to_bytes())
        })
        .collect();
    assert_eq!(patched_keys, keys);
    for (input, output) in encodings.iter().zip(&keys) {
        if let Some(output) = output {
            assert_eq!(input, output);
        }
    }
    let cases = cases::cases();
    let expected: Vec<_> = cases
        .iter()
        .map(|case| {
            let individual = cases::verify(case);
            let batch = cases::verify_batch(std::slice::from_ref(case));
            assert_eq!(individual, batch);
            assert_eq!(individual, cases::verify_patched(case));
            assert_eq!(batch, cases::verify_batch_patched(std::slice::from_ref(case)));
            (individual, batch)
        })
        .collect();
    let valid: Vec<_> = cases.iter().filter(|case| cases::verify(case)).cloned().collect();
    assert!(cases::verify_batch(&valid));
    assert!(cases::verify_batch_patched(&valid));
    let mut mixed = valid.clone();
    mixed.push(cases.last().unwrap().clone());
    assert!(!cases::verify_batch(&mixed));
    assert!(!cases::verify_batch_patched(&mixed));
    stdin.write(&encodings);
    stdin.write(&cases);
    stdin.write(&valid);
    stdin.write(&mixed);
    move |mut public| {
        assert_eq!(public.read::<Vec<Option<[u8; 32]>>>(), keys);
        assert_eq!(public.read::<Vec<(bool, bool)>>(), expected);
        assert!(public.read::<bool>());
        assert!(!public.read::<bool>());
    }
}
