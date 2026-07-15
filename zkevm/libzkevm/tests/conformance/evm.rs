//! Conformance for the remaining EVM precompiles against the full
//! go-ethereum vector suites: BN254 (0x06–0x08), ecrecover (0x01),
//! ripemd160 (0x03), modexp (0x05), blake2f (0x09), KZG point evaluation
//! (0x0a), and p256verify (0x100).
//!
//! NOTE: go-ethereum ships no golden vector file for ripemd160, so unlike
//! the other precompiles here its vectors are inlined rather than loaded
//! from `tests/data/geth/`. They come from the RIPEMD-160 designers'
//! official "test values" page (A. Bosselaers, KU Leuven COSIC:
//! https://homes.esat.kuleuven.be/~bosselae/ripemd160.html)

use crate::support::*;
use crate::{EFAIL, EOK};
use zkevm::precompile::blake2f::zkvm_blake2f;
use zkevm::precompile::bn254::*;
use zkevm::precompile::hash::{zkvm_keccak256, zkvm_ripemd160, zkvm_sha256};
use zkevm::precompile::kzg::zkvm_kzg_point_eval;
use zkevm::precompile::modexp::zkvm_modexp;
use zkevm::precompile::secp256k1::zkvm_secp256k1_ecrecover;
use zkevm::precompile::secp256r1::zkvm_secp256r1_verify;
use zkevm::precompile::types::*;

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = ZkvmBytes32 { data: [0u8; 32] };
    let status = unsafe { zkvm_keccak256(data.as_ptr(), data.len(), &mut out) };
    assert_eq!(status, EOK);
    out.data
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = ZkvmBytes32 { data: [0u8; 32] };
    let status = unsafe { zkvm_sha256(data.as_ptr(), data.len(), &mut out) };
    assert_eq!(status, EOK);
    out.data
}

fn run_ripemd160(data: &[u8]) -> [u8; 32] {
    let mut out = ZkvmBytes32 { data: [0u8; 32] };
    let status = unsafe { zkvm_ripemd160(data.as_ptr(), data.len(), &mut out) };
    assert_eq!(status, EOK);
    out.data
}

/// Assert `ripemd160(data)` is `digest_hex` right-aligned in the 32-byte
/// output word: 12 zero bytes followed by the 20-byte digest.
fn assert_ripemd160(data: &[u8], digest_hex: &str) {
    let digest = unhex(digest_hex);
    assert_eq!(digest.len(), 20, "RIPEMD-160 digest is 20 bytes");
    let out = run_ripemd160(data);
    assert_eq!(&out[..12], &[0u8; 12][..], "leading 12 bytes must be zero");
    assert_eq!(&out[12..], digest.as_slice(), "digest mismatch for {digest_hex}");
}

#[test]
fn ripemd160() {
    // Reference vectors from the RIPEMD-160 designers' "test values" page
    // (A. Bosselaers, KU Leuven COSIC:
    // https://homes.esat.kuleuven.be/~bosselae/ripemd160.html), the same
    // set evmone checks in test/unittests/precompiles_ripemd160_test.cpp.
    let string_cases: &[(&[u8], &str)] = &[
        (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
        (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
        (b"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
        ),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "b0e20b6e3116640286ed3a87a5713079b21f5189",
        ),
        (
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
        ),
        (
            b"The quick brown fox jumps over the lazy dog",
            "37f332f68db77bd9d7edd4969571ad671cf9dd3b",
        ),
    ];
    for (input, digest_hex) in string_cases {
        assert_ripemd160(input, digest_hex);
    }

    // `len` repetitions of 'a'
    let length_cases: &[(usize, &str)] = &[
        (0, "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        (1, "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
        (54, "a57fa1577740fd73b6859dd20e090cdac4d2af36"),
        (55, "0d8a8c9063a48576a7c97e9f95253a6e53ff6765"),
        (56, "e72334b46c83cc70bef979e15453706c95b888be"),
        (57, "eed82d19d597ab275b550ff3d6e0bc2a75350388"),
        (63, "e640041293fe663b9bf3f8c21ffecac03819e6b2"),
        (64, "9dfb7d374ad924f3f88de96291c33e9abed53e32"),
        (65, "99724bb11811e7166af38f671b6a082d8ab4960b"),
        (119, "23e398ff2bac815aa1bbb57ca2a669c841872919"),
        (120, "c476770a6dae31fcee8d25efe6559a05c8024595"),
        (121, "725c88a6f41605e99477a1478607d3fe25ced606"),
        (127, "64f2d68b85f394e2e4f49009c4bd50224c2698ed"),
        (128, "8dfdfb32b2ed5cb41a73478b4fd60cc5b4648b15"),
        (129, "62bb9091f499f294f15aa5b951df4d9744d50cf2"),
        (1_000_000, "52783243c1697bdbe16d37f97f68f08325dc1528"),
    ];
    for (len, digest_hex) in length_cases {
        assert_ripemd160(&vec![b'a'; *len], digest_hex);
    }

    // null data with a non-zero len, and a null output, are both errors.
    let mut out = ZkvmBytes32 { data: [0u8; 32] };
    assert_eq!(unsafe { zkvm_ripemd160(std::ptr::null(), 4, &mut out) }, EFAIL);
    let data = [1u8, 2, 3];
    assert_eq!(unsafe { zkvm_ripemd160(data.as_ptr(), data.len(), std::ptr::null_mut()) }, EFAIL);
}

// --- BN254 (EIP-196/197). Inputs use EVM `getData` padding; the wire
// --- point layout already matches the ABI structs byte-for-byte.

fn run_bn_add(input: &[u8]) -> Option<Vec<u8>> {
    let data = get_data(input, 0, 128);
    let p1 = ZkvmBytes64 { data: data[0..64].try_into().unwrap() };
    let p2 = ZkvmBytes64 { data: data[64..128].try_into().unwrap() };
    let mut out = ZkvmBytes64 { data: [0u8; 64] };
    let status = unsafe { zkvm_bn254_g1_add(&p1, &p2, &mut out) };
    (status == EOK).then(|| out.data.to_vec())
}

fn run_bn_mul(input: &[u8]) -> Option<Vec<u8>> {
    let data = get_data(input, 0, 96);
    let p = ZkvmBytes64 { data: data[0..64].try_into().unwrap() };
    let s = ZkvmBytes32 { data: data[64..96].try_into().unwrap() };
    let mut out = ZkvmBytes64 { data: [0u8; 64] };
    let status = unsafe { zkvm_bn254_g1_mul(&p, &s, &mut out) };
    (status == EOK).then(|| out.data.to_vec())
}

fn run_bn_pairing(input: &[u8]) -> Option<Vec<u8>> {
    if !input.len().is_multiple_of(192) {
        return None;
    }
    let mut pairs = Vec::with_capacity(input.len() / 192);
    for chunk in input.chunks_exact(192) {
        pairs.push(Bn254PairingPair {
            g1: ZkvmBytes64 { data: chunk[0..64].try_into().unwrap() },
            g2: ZkvmBytes128 { data: chunk[64..192].try_into().unwrap() },
        });
    }
    let mut verified = false;
    let status = unsafe { zkvm_bn254_pairing(pairs.as_ptr(), pairs.len(), &mut verified) };
    (status == EOK).then(|| be_word(verified as u64).to_vec())
}

#[test]
fn bn254_add() {
    for v in load_geth("bn256Add") {
        let got = run_bn_add(&unhex(&v.input)).unwrap_or_else(|| panic!("{}: rejected", v.name));
        assert_eq!(got, unhex(v.expected.as_ref().unwrap()), "{}", v.name);
    }
}

#[test]
fn bn254_mul() {
    for v in load_geth("bn256ScalarMul") {
        let got = run_bn_mul(&unhex(&v.input)).unwrap_or_else(|| panic!("{}: rejected", v.name));
        assert_eq!(got, unhex(v.expected.as_ref().unwrap()), "{}", v.name);
    }
}

#[test]
fn bn254_pairing() {
    for v in load_geth("bn256Pairing") {
        let got =
            run_bn_pairing(&unhex(&v.input)).unwrap_or_else(|| panic!("{}: rejected", v.name));
        assert_eq!(got, unhex(v.expected.as_ref().unwrap()), "{}", v.name);
    }
}

// --- ecrecover (0x01). The EVM precompile never errors: every failure
// --- mode returns empty output. The glue maps ZKVM_EFAIL accordingly.

fn run_ecrecover(input: &[u8]) -> Vec<u8> {
    let data = get_data(input, 0, 128);
    // v is a 32-byte word that must be exactly 27 or 28.
    if data[32..63].iter().any(|&b| b != 0) || !matches!(data[63], 27 | 28) {
        return Vec::new();
    }
    let msg = ZkvmBytes32 { data: data[0..32].try_into().unwrap() };
    let sig = ZkvmBytes64 { data: data[64..128].try_into().unwrap() };
    let mut pubkey = ZkvmBytes64 { data: [0u8; 64] };
    let status = unsafe { zkvm_secp256k1_ecrecover(&msg, &sig, data[63] - 27, &mut pubkey) };
    if status != EOK {
        // Unrecoverable signature → empty output per the EVM spec.
        return Vec::new();
    }
    // address = keccak256(pubkey)[12..], left-padded to a 32-byte word.
    let mut out = vec![0u8; 32];
    out[12..].copy_from_slice(&keccak256(&pubkey.data)[12..]);
    out
}

#[test]
fn ecrecover() {
    for v in load_geth("ecRecover") {
        let expected = unhex(v.expected.as_deref().unwrap_or(""));
        assert_eq!(run_ecrecover(&unhex(&v.input)), expected, "{}", v.name);
    }
}

// --- modexp (0x05, EIP-198).

fn parse_len_word(word: &[u8]) -> Option<usize> {
    // Cap declared lengths: the official vectors stay far below this;
    // a vector exceeding it should fail loudly, not OOM the test.
    if word[..24].iter().any(|&b| b != 0) {
        return None;
    }
    let v = u64::from_be_bytes(word[24..32].try_into().unwrap());
    (v <= (1 << 20)).then_some(v as usize)
}

fn run_modexp(input: &[u8]) -> Option<Vec<u8>> {
    let header = get_data(input, 0, 96);
    let base_len = parse_len_word(&header[0..32])?;
    let exp_len = parse_len_word(&header[32..64])?;
    let mod_len = parse_len_word(&header[64..96])?;
    let body = get_data(input, 96, base_len + exp_len + mod_len);
    let base = &body[0..base_len];
    let exp = &body[base_len..base_len + exp_len];
    let modulus = &body[base_len + exp_len..];
    let mut out = vec![0u8; mod_len];
    let status = unsafe {
        zkvm_modexp(
            base.as_ptr(),
            base_len,
            exp.as_ptr(),
            exp_len,
            modulus.as_ptr(),
            mod_len,
            out.as_mut_ptr(),
        )
    };
    (status == EOK).then_some(out)
}

#[test]
fn modexp() {
    for file in ["modexp", "modexp_eip2565", "modexp_eip7883"] {
        for v in load_geth(file) {
            let got = run_modexp(&unhex(&v.input))
                .unwrap_or_else(|| panic!("{file}/{}: rejected", v.name));
            assert_eq!(got, unhex(v.expected.as_ref().unwrap()), "{file}/{}", v.name);
        }
    }
}

// --- blake2f (0x09, EIP-152).

fn run_blake2f(input: &[u8]) -> Option<Vec<u8>> {
    if input.len() != 213 {
        return None;
    }
    let rounds = u32::from_be_bytes(input[0..4].try_into().unwrap());
    let mut h = ZkvmBytes64 { data: input[4..68].try_into().unwrap() };
    let m = ZkvmBytes128 { data: input[68..196].try_into().unwrap() };
    let t = ZkvmBytes16 { data: input[196..212].try_into().unwrap() };
    let status = unsafe { zkvm_blake2f(rounds, &mut h, &m, &t, input[212]) };
    (status == EOK).then(|| h.data.to_vec())
}

#[test]
fn blake2f() {
    for v in load_geth("blake2F") {
        let got = run_blake2f(&unhex(&v.input)).unwrap_or_else(|| panic!("{}: rejected", v.name));
        assert_eq!(got, unhex(v.expected.as_ref().unwrap()), "{}", v.name);
    }
    for v in load_geth("fail-blake2f") {
        assert!(run_blake2f(&unhex(&v.input)).is_none(), "{}: accepted invalid input", v.name);
    }
}

// --- KZG point evaluation (0x0a, EIP-4844). The versioned-hash binding
// --- is EVM glue on top of the raw `zkvm_kzg_point_eval` ABI.

const FIELD_ELEMENTS_PER_BLOB: u64 = 4096;
const BLS_MODULUS_HEX: &str = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";

fn run_point_evaluation(input: &[u8]) -> Option<Vec<u8>> {
    if input.len() != 192 {
        return None;
    }
    let commitment = ZkvmBytes48 { data: input[96..144].try_into().unwrap() };
    // versioned_hash must equal 0x01 || sha256(commitment)[1..].
    let mut vh = sha256(&commitment.data);
    vh[0] = 0x01;
    if vh != input[0..32] {
        return None;
    }
    let z = ZkvmBytes32 { data: input[32..64].try_into().unwrap() };
    let y = ZkvmBytes32 { data: input[64..96].try_into().unwrap() };
    let proof = ZkvmBytes48 { data: input[144..192].try_into().unwrap() };
    let mut verified = false;
    let status = unsafe { zkvm_kzg_point_eval(&commitment, &z, &y, &proof, &mut verified) };
    if status != EOK || !verified {
        return None;
    }
    let mut out = be_word(FIELD_ELEMENTS_PER_BLOB).to_vec();
    out.extend_from_slice(&unhex(BLS_MODULUS_HEX));
    Some(out)
}

#[test]
fn point_evaluation() {
    for v in load_geth("pointEvaluation") {
        let got = run_point_evaluation(&unhex(&v.input));
        match (&v.expected, &v.expected_error) {
            (Some(expected), _) if !expected.is_empty() => {
                let got = got.unwrap_or_else(|| panic!("{}: rejected", v.name));
                assert_eq!(got, unhex(expected), "{}", v.name);
            }
            _ => assert!(got.is_none(), "{}: accepted invalid input", v.name),
        }
    }
}

// --- p256verify (0x100, EIP-7951): valid → 32-byte 1, anything else →
// --- empty output.

fn run_p256_verify(input: &[u8]) -> Vec<u8> {
    if input.len() != 160 {
        return Vec::new();
    }
    let msg = ZkvmBytes32 { data: input[0..32].try_into().unwrap() };
    let sig = ZkvmBytes64 { data: input[32..96].try_into().unwrap() };
    let pubkey = ZkvmBytes64 { data: input[96..160].try_into().unwrap() };
    let mut verified = false;
    let status = unsafe { zkvm_secp256r1_verify(&msg, &sig, &pubkey, &mut verified) };
    if status == EOK && verified {
        be_word(1).to_vec()
    } else {
        Vec::new()
    }
}

#[test]
fn p256_verify() {
    for v in load_geth("p256Verify") {
        let expected = unhex(v.expected.as_deref().unwrap_or(""));
        assert_eq!(run_p256_verify(&unhex(&v.input)), expected, "{}", v.name);
    }
}
