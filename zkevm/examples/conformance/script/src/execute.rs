//! Execute the conformance guest over the full official vector suites.
//!
//! The host side converts the vendored vectors (EVM wire format) to
//! C-ABI batches — single-sourcing the conversion glue from the
//! libzkevm host conformance tests — and runs ONE executor invocation
//! per family, so the whole suite costs four guest executions instead
//! of hundreds. The guest exercises the real syscall-routed accelerator
//! paths; wire-level rejection vectors that never reach the ABI are
//! skipped here (the host test suite covers them) and logged.
//!
//! `ZKEVM_CONFORMANCE_STRIDE` (default 5) samples the ~950-case
//! Wycheproof suites to keep executor time CI-friendly; set it to 1 for
//! the full run. All geth suites always run in full.

use sha2::Digest;
use sp1_sdk::{include_elf, utils, Elf, Prover, ProverClient, SP1Stdin};
use tracing::info;

// Single source of truth for vector loading + wire↔ABI conversion.
#[allow(dead_code)]
#[path = "../../ops.rs"]
mod ops;
#[allow(dead_code)]
#[path = "../../../../libzkevm/tests/conformance/support.rs"]
mod support;

use ops::*;
use support::*;

const ELF: Elf = include_elf!("conformance");

struct Batch {
    name: &'static str,
    data: Vec<u8>,
    descriptions: Vec<String>,
}

impl Batch {
    fn new(name: &'static str) -> Self {
        Self { name, data: Vec::new(), descriptions: Vec::new() }
    }

    /// `expected: None` means the accelerator must return `ZKVM_EFAIL`.
    fn push(&mut self, op: u8, input: &[u8], expected: Option<&[u8]>, description: String) {
        self.data.push(op);
        self.data.push(u8::from(expected.is_none()));
        self.data.extend_from_slice(&(input.len() as u32).to_le_bytes());
        self.data.extend_from_slice(input);
        let expected = expected.unwrap_or(&[]);
        self.data.extend_from_slice(&(expected.len() as u32).to_le_bytes());
        self.data.extend_from_slice(expected);
        self.descriptions.push(description);
    }

    fn finish(mut self) -> Self {
        self.data.push(OP_END);
        self
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

/// Add a geth suite: all success vectors, plus the fail vectors whose
/// rejection is ABI-level (wire-level rejections never reach the guest
/// and are covered by the host conformance tests).
fn add_geth_suite(
    batch: &mut Batch,
    file: &str,
    fail_file: Option<&str>,
    op: u8,
    conv_input: impl Fn(&[u8]) -> Option<Vec<u8>>,
    conv_expected: impl Fn(&[u8]) -> Vec<u8>,
) {
    for v in load_geth(file) {
        let input = conv_input(&unhex(&v.input))
            .unwrap_or_else(|| panic!("{file}/{}: valid vector failed wire conversion", v.name));
        let expected = conv_expected(&unhex(v.expected.as_ref().unwrap()));
        batch.push(op, &input, Some(&expected), format!("{file}/{}", v.name));
    }
    if let Some(fail_file) = fail_file {
        let (mut included, mut wire_level) = (0u32, 0u32);
        for v in load_geth(fail_file) {
            match conv_input(&unhex(&v.input)) {
                Some(input) => {
                    batch.push(op, &input, None, format!("{fail_file}/{}", v.name));
                    included += 1;
                }
                None => wire_level += 1,
            }
        }
        info!(file = fail_file, included, skipped_wire_level = wire_level, "fail vectors");
    }
}

fn conv_g1_pair(input: &[u8]) -> Option<Vec<u8>> {
    (input.len() == 256).then_some(())?;
    Some(
        [wire_g1_to_abi(&input[0..128])?.as_slice(), wire_g1_to_abi(&input[128..256])?.as_slice()]
            .concat(),
    )
}

fn conv_g2_pair(input: &[u8]) -> Option<Vec<u8>> {
    (input.len() == 512).then_some(())?;
    Some(
        [wire_g2_to_abi(&input[0..256])?.as_slice(), wire_g2_to_abi(&input[256..512])?.as_slice()]
            .concat(),
    )
}

fn conv_g1_msm(input: &[u8]) -> Option<Vec<u8>> {
    (!input.is_empty() && input.len().is_multiple_of(160)).then_some(())?;
    let mut out = Vec::with_capacity(input.len() / 160 * 128);
    for chunk in input.chunks_exact(160) {
        out.extend_from_slice(&wire_g1_to_abi(&chunk[0..128])?);
        out.extend_from_slice(&chunk[128..160]);
    }
    Some(out)
}

fn conv_g2_msm(input: &[u8]) -> Option<Vec<u8>> {
    (!input.is_empty() && input.len().is_multiple_of(288)).then_some(())?;
    let mut out = Vec::with_capacity(input.len() / 288 * 224);
    for chunk in input.chunks_exact(288) {
        out.extend_from_slice(&wire_g2_to_abi(&chunk[0..256])?);
        out.extend_from_slice(&chunk[256..288]);
    }
    Some(out)
}

fn conv_bls_pairing(input: &[u8]) -> Option<Vec<u8>> {
    (!input.is_empty() && input.len().is_multiple_of(384)).then_some(())?;
    let mut out = Vec::with_capacity(input.len() / 384 * 288);
    for chunk in input.chunks_exact(384) {
        out.extend_from_slice(&wire_g1_to_abi(&chunk[0..128])?);
        out.extend_from_slice(&wire_g2_to_abi(&chunk[128..384])?);
    }
    Some(out)
}

fn conv_map_fp(input: &[u8]) -> Option<Vec<u8>> {
    (input.len() == 64).then_some(())?;
    Some(unpad_fp(input)?.to_vec())
}

fn conv_map_fp2(input: &[u8]) -> Option<Vec<u8>> {
    (input.len() == 128).then_some(())?;
    Some([unpad_fp(&input[0..64])?.as_slice(), unpad_fp(&input[64..128])?.as_slice()].concat())
}

fn exp_g1(e: &[u8]) -> Vec<u8> {
    wire_g1_to_abi(e).expect("expected output is a valid wire G1").to_vec()
}

fn exp_g2(e: &[u8]) -> Vec<u8> {
    wire_g2_to_abi(e).expect("expected output is a valid wire G2").to_vec()
}

fn exp_bool_word(e: &[u8]) -> Vec<u8> {
    vec![e[31]]
}

fn bls_batch() -> Batch {
    let mut b = Batch::new("bls12-381");
    add_geth_suite(&mut b, "blsG1Add", Some("fail-blsG1Add"), OP_G1_ADD, conv_g1_pair, exp_g1);
    add_geth_suite(&mut b, "blsG1Mul", Some("fail-blsG1Mul"), OP_G1_MSM, conv_g1_msm, exp_g1);
    add_geth_suite(
        &mut b,
        "blsG1MultiExp",
        Some("fail-blsG1MultiExp"),
        OP_G1_MSM,
        conv_g1_msm,
        exp_g1,
    );
    add_geth_suite(&mut b, "blsG2Add", Some("fail-blsG2Add"), OP_G2_ADD, conv_g2_pair, exp_g2);
    add_geth_suite(&mut b, "blsG2Mul", Some("fail-blsG2Mul"), OP_G2_MSM, conv_g2_msm, exp_g2);
    add_geth_suite(
        &mut b,
        "blsG2MultiExp",
        Some("fail-blsG2MultiExp"),
        OP_G2_MSM,
        conv_g2_msm,
        exp_g2,
    );
    add_geth_suite(
        &mut b,
        "blsPairing",
        Some("fail-blsPairing"),
        OP_BLS_PAIRING,
        conv_bls_pairing,
        exp_bool_word,
    );
    add_geth_suite(&mut b, "blsMapG1", Some("fail-blsMapG1"), OP_MAP_FP_G1, conv_map_fp, exp_g1);
    add_geth_suite(&mut b, "blsMapG2", Some("fail-blsMapG2"), OP_MAP_FP2_G2, conv_map_fp2, exp_g2);
    b.finish()
}

fn bn254_batch() -> Batch {
    let mut b = Batch::new("bn254");
    add_geth_suite(
        &mut b,
        "bn256Add",
        None,
        OP_BN_ADD,
        |i| Some(get_data(i, 0, 128)),
        <[u8]>::to_vec,
    );
    add_geth_suite(
        &mut b,
        "bn256ScalarMul",
        None,
        OP_BN_MUL,
        |i| Some(get_data(i, 0, 96)),
        <[u8]>::to_vec,
    );
    add_geth_suite(
        &mut b,
        "bn256Pairing",
        None,
        OP_BN_PAIRING,
        |i| i.len().is_multiple_of(192).then(|| i.to_vec()),
        exp_bool_word,
    );
    b.finish()
}

fn ecdsa_batch(stride: usize) -> Batch {
    let mut b = Batch::new("ecdsa");

    // ecrecover: geth carries the *address*; the guest checks the raw
    // recovered pubkey, so derive it with the host fallback path of the
    // same accelerator and sanity-check it against the address.
    let (mut included, mut glue_level) = (0u32, 0u32);
    for v in load_geth("ecRecover") {
        let data = get_data(&unhex(&v.input), 0, 128);
        let v_ok = data[32..63].iter().all(|&x| x == 0) && matches!(data[63], 27 | 28);
        if !v_ok {
            glue_level += 1;
            continue;
        }
        let mut input = Vec::with_capacity(97);
        input.extend_from_slice(&data[0..32]);
        input.extend_from_slice(&data[64..128]);
        input.push(data[63] - 27);

        let expected_address = unhex(v.expected.as_deref().unwrap_or(""));
        if expected_address.is_empty() {
            b.push(OP_ECRECOVER, &input, None, format!("ecRecover/{}", v.name));
        } else {
            let pubkey = host_ecrecover(&input).unwrap_or_else(|| {
                panic!("ecRecover/{}: host recovery failed on a valid vector", v.name)
            });
            let mut address = vec![0u8; 32];
            address[12..].copy_from_slice(&host_keccak256(&pubkey)[12..]);
            assert_eq!(address, expected_address, "ecRecover/{}: host pubkey mismatch", v.name);
            b.push(OP_ECRECOVER, &input, Some(&pubkey), format!("ecRecover/{}", v.name));
        }
        included += 1;
    }
    info!(file = "ecRecover", included, skipped_glue_level = glue_level, "ecrecover vectors");

    // p256verify (EIP-7951): already in the ABI layout.
    for v in load_geth("p256Verify") {
        let input = unhex(&v.input);
        if input.len() != 160 {
            continue; // glue-level length rejection, host-tested
        }
        let expected = unhex(v.expected.as_deref().unwrap_or(""));
        let verified = [u8::from(!expected.is_empty() && expected[31] == 1)];
        b.push(OP_R1_VERIFY, &input, Some(&verified), format!("p256Verify/{}", v.name));
    }

    add_wycheproof(&mut b, "ecdsa_secp256k1_sha256_test", OP_K1_VERIFY, stride);
    add_wycheproof(&mut b, "ecdsa_secp256r1_sha256_test", OP_R1_VERIFY, stride);
    b.finish()
}

fn add_wycheproof(b: &mut Batch, file: &str, op: u8, stride: usize) {
    let suite = load_wycheproof(file);
    let (mut included, mut strided, mut der_level, mut acceptable) = (0u32, 0u32, 0u32, 0u32);
    let mut index = 0usize;
    for group in &suite.test_groups {
        let uncompressed = hex::decode(&group.public_key.uncompressed).unwrap();
        let pubkey = &uncompressed[1..65];
        for case in &group.tests {
            if case.result == "acceptable" {
                acceptable += 1;
                continue;
            }
            index += 1;
            if !index.is_multiple_of(stride) {
                strided += 1;
                continue;
            }
            let Some(sig) = parse_der_signature(&hex::decode(&case.sig).unwrap()) else {
                der_level += 1; // DER-level rejection, host-tested
                continue;
            };
            let mut input = Vec::with_capacity(160);
            input.extend_from_slice(&sha256(&hex::decode(&case.msg).unwrap()));
            input.extend_from_slice(&sig);
            input.extend_from_slice(pubkey);
            let verified = [u8::from(case.result == "valid")];
            b.push(
                op,
                &input,
                Some(&verified),
                format!("{file}/tc{} ({})", case.tc_id, case.comment),
            );
            included += 1;
        }
    }
    info!(file, included, strided, skipped_der_level = der_level, acceptable, "wycheproof");
}

fn misc_batch() -> Batch {
    let mut b = Batch::new("modexp+blake2f+kzg");

    for file in ["modexp", "modexp_eip2565", "modexp_eip7883"] {
        add_geth_suite(&mut b, file, None, OP_MODEXP, conv_modexp, <[u8]>::to_vec);
    }

    add_geth_suite(
        &mut b,
        "blake2F",
        Some("fail-blake2f"),
        OP_BLAKE2F,
        conv_blake2f,
        <[u8]>::to_vec,
    );

    // KZG point evaluation: the versioned-hash binding is EVM glue; only
    // vectors passing it reach the ABI.
    let (mut included, mut glue_level) = (0u32, 0u32);
    for v in load_geth("pointEvaluation") {
        let input = unhex(&v.input);
        let hash_ok = input.len() == 192 && {
            let mut vh = sha256(&input[96..144]);
            vh[0] = 0x01;
            vh == input[0..32]
        };
        if !hash_ok {
            glue_level += 1;
            continue;
        }
        let abi_input =
            [&input[96..144], &input[32..64], &input[64..96], &input[144..192]].concat();
        let valid = v.expected.as_deref().is_some_and(|e| !e.is_empty());
        b.push(
            OP_KZG_POINT_EVAL,
            &abi_input,
            Some(&[u8::from(valid)]),
            format!("pointEvaluation/{}", v.name),
        );
        included += 1;
    }
    info!(file = "pointEvaluation", included, skipped_glue_level = glue_level, "kzg vectors");

    b.finish()
}

fn conv_modexp(input: &[u8]) -> Option<Vec<u8>> {
    let header = get_data(input, 0, 96);
    let len_at = |i: usize| -> Option<usize> {
        let word = &header[i * 32..(i + 1) * 32];
        if word[..24].iter().any(|&x| x != 0) {
            return None;
        }
        let v = u64::from_be_bytes(word[24..32].try_into().unwrap());
        (v <= (1 << 20)).then_some(v as usize)
    };
    let (base_len, exp_len, mod_len) = (len_at(0)?, len_at(1)?, len_at(2)?);
    let body = get_data(input, 96, base_len + exp_len + mod_len);
    let mut out = Vec::with_capacity(12 + body.len());
    out.extend_from_slice(&(base_len as u32).to_le_bytes());
    out.extend_from_slice(&(exp_len as u32).to_le_bytes());
    out.extend_from_slice(&(mod_len as u32).to_le_bytes());
    out.extend_from_slice(&body);
    Some(out)
}

fn conv_blake2f(input: &[u8]) -> Option<Vec<u8>> {
    (input.len() == 213).then_some(())?;
    let rounds = u32::from_be_bytes(input[0..4].try_into().unwrap());
    let mut out = Vec::with_capacity(213);
    out.extend_from_slice(&rounds.to_le_bytes());
    out.extend_from_slice(&input[4..213]);
    Some(out)
}

fn host_ecrecover(input: &[u8]) -> Option<Vec<u8>> {
    use zkevm::precompile::types::{ZkvmBytes32, ZkvmBytes64};
    let msg = ZkvmBytes32 { data: input[0..32].try_into().unwrap() };
    let sig = ZkvmBytes64 { data: input[32..96].try_into().unwrap() };
    let mut out = ZkvmBytes64 { data: [0u8; 64] };
    let status = unsafe {
        zkevm::precompile::secp256k1::zkvm_secp256k1_ecrecover(&msg, &sig, input[96], &mut out)
    };
    (status == 0).then(|| out.data.to_vec())
}

fn host_keccak256(data: &[u8]) -> [u8; 32] {
    use zkevm::precompile::types::ZkvmBytes32;
    let mut out = ZkvmBytes32 { data: [0u8; 32] };
    let status =
        unsafe { zkevm::precompile::hash::zkvm_keccak256(data.as_ptr(), data.len(), &mut out) };
    assert_eq!(status, 0);
    out.data
}

async fn run_batch(client: &impl Prover, batch: Batch) {
    let cases = batch.descriptions.len();
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&batch.data);
    let (public_values, report) = client.execute(ELF, stdin).await.unwrap();

    let summary = public_values.as_slice();
    let total = u32::from_le_bytes(summary[0..4].try_into().unwrap()) as usize;
    let failures = u32::from_le_bytes(summary[4..8].try_into().unwrap()) as usize;
    assert_eq!(total, cases, "{}: guest ran {total} of {cases} cases", batch.name);

    info!(
        batch = batch.name,
        cases,
        cycles = report.total_instruction_count() + report.total_syscall_count(),
        "executed conformance batch",
    );

    if failures > 0 {
        for entry in summary[8..].chunks_exact(5).take(failures) {
            let index = u32::from_le_bytes(entry[0..4].try_into().unwrap()) as usize;
            let op = entry[4];
            tracing::error!(batch = batch.name, op, case = %batch.descriptions[index], "FAILED");
        }
        panic!("{}: {failures}/{cases} conformance cases failed in the executor", batch.name);
    }
}

#[tokio::main]
async fn main() {
    utils::setup_logger();
    std::env::set_var(
        "ZKEVM_CONFORMANCE_DATA",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../../libzkevm/tests/data"),
    );
    let stride = std::env::var("ZKEVM_CONFORMANCE_STRIDE")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&s| s >= 1)
        .unwrap_or(5);
    if stride > 1 {
        info!(stride, "sampling wycheproof suites; set ZKEVM_CONFORMANCE_STRIDE=1 for full runs");
    }

    let client = ProverClient::builder().light().build().await;
    for batch in [bls_batch(), bn254_batch(), ecdsa_batch(stride), misc_batch()] {
        run_batch(&client, batch).await;
    }
    info!("all conformance batches passed in the executor");
}
