use sha3::digest::{ExtendableOutputReset, Reset, Update, XofReader};

fn check_case<H>(new: impl Fn() -> H, input: &[u8], output_len: usize) -> Vec<u8>
where
    H: Update + ExtendableOutputReset + Reset + Clone,
    H::Reader: Clone,
{
    let mut hasher = new();
    hasher.update(input);
    let mut expected = vec![0; output_len];
    hasher.finalize_xof().read(&mut expected);

    let mut hasher = new();
    hasher.update(&[]);
    for chunk in input.chunks(17) {
        hasher.update(chunk);
    }
    let mut reader = hasher.finalize_xof_reset();
    let mut streamed = vec![0; output_len];
    reader.read(&mut []);
    for chunk in streamed.chunks_mut(19) {
        reader.read(chunk);
    }
    assert_eq!(streamed, expected);

    hasher.update(input);
    hasher.finalize_xof_reset().read(&mut streamed);
    assert_eq!(streamed, expected);
    hasher.update(b"discard this input");
    hasher.reset();
    hasher.update(input);
    hasher.finalize_xof().read(&mut streamed);
    assert_eq!(streamed, expected);

    let split = input.len() / 2;
    let mut hasher = new();
    hasher.update(&input[..split]);
    let mut cloned = hasher.clone();
    hasher.update(&input[split..]);
    cloned.update(&input[split..]);
    cloned.finalize_xof().read(&mut streamed);
    assert_eq!(streamed, expected);

    let mut reader = hasher.finalize_xof();
    let split = output_len / 2;
    reader.read(&mut streamed[..split]);
    let mut cloned_reader = reader.clone();
    reader.read(&mut streamed[split..]);
    assert_eq!(streamed, expected);
    cloned_reader.read(&mut streamed[split..]);
    assert_eq!(streamed, expected);
    expected
}

fn boundary_cases<H>(new: impl Fn() -> H, rate: usize) -> Vec<Vec<u8>>
where
    H: Update + ExtendableOutputReset + Reset + Clone,
    H::Reader: Clone,
{
    let mut outputs = Vec::new();
    let input_lengths =
        [0, 1, rate - 1, rate, rate + 1, 2 * rate - 1, 2 * rate, 2 * rate + 1, 1024];
    let output_lengths = [0, 1, rate - 1, rate, rate + 1, 2 * rate - 1, 2 * rate, 2 * rate + 1];
    for input_len in input_lengths {
        let input = (0..input_len).map(|i| (i.wrapping_mul(71) % 251) as u8).collect::<Vec<_>>();
        for output_len in output_lengths {
            outputs.push(check_case(&new, &input, output_len));
        }
    }
    outputs
}

pub fn turbo_shake_cases() -> Vec<Vec<u8>> {
    let mut outputs = Vec::new();
    for domain in [0x01, 0x06, 0x1f, 0x7f] {
        outputs.extend(boundary_cases(
            || sha3::TurboShake128::from_core(sha3::TurboShake128Core::new(domain)),
            168,
        ));
        outputs.extend(boundary_cases(
            || sha3::TurboShake256::from_core(sha3::TurboShake256Core::new(domain)),
            136,
        ));
    }
    outputs
}

pub fn shake_cases() -> Vec<Vec<u8>> {
    let mut outputs = boundary_cases(sha3::Shake128::default, 168);
    outputs.extend(boundary_cases(sha3::Shake256::default, 136));
    outputs
}
