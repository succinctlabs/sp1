//! Vector loading and EVM-wire ↔ C-ABI conversion glue.

use serde::Deserialize;
use std::path::PathBuf;

/// One go-ethereum precompile test vector. Success files carry
/// `Expected`; `fail-*` files carry `ExpectedError` instead.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct GethVector {
    pub input: String,
    #[serde(default)]
    pub expected: Option<String>,
    #[serde(default)]
    pub expected_error: Option<String>,
    pub name: String,
}

/// Root of the vendored vector data. `ZKEVM_CONFORMANCE_DATA` overrides
/// the compile-time default so this file can be `#[path]`-included from
/// other crates (the executor conformance script) — `env!` resolves to
/// the *including* crate's manifest dir.
pub fn data_root() -> PathBuf {
    std::env::var_os("ZKEVM_CONFORMANCE_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data"))
}

/// Load `<data_root>/geth/<name>.json` (a JSON array of vectors).
pub fn load_geth(name: &str) -> Vec<GethVector> {
    let path = data_root().join("geth").join(format!("{name}.json"));
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let vectors: Vec<GethVector> =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
    assert!(!vectors.is_empty(), "{name}.json is empty");
    vectors
}

pub fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("bad hex in vector: {e}"))
}

// ---------------------------------------------------------------------
// Wycheproof (v1 schema, EcdsaVerify)
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct WycheproofFile {
    #[serde(rename = "testGroups")]
    pub test_groups: Vec<WycheproofGroup>,
}

#[derive(Deserialize)]
pub struct WycheproofGroup {
    #[serde(rename = "publicKey")]
    pub public_key: WycheproofKey,
    pub tests: Vec<WycheproofCase>,
}

#[derive(Deserialize)]
pub struct WycheproofKey {
    pub uncompressed: String,
}

#[derive(Deserialize)]
pub struct WycheproofCase {
    #[serde(rename = "tcId")]
    pub tc_id: u32,
    pub comment: String,
    pub msg: String,
    pub sig: String,
    pub result: String,
}

/// Load `<data_root>/wycheproof/<name>.json`.
pub fn load_wycheproof(name: &str) -> WycheproofFile {
    let path = data_root().join("wycheproof").join(format!("{name}.json"));
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Strict-DER `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`
/// → 64-byte left-padded big-endian `r || s`. Any deviation (BER long
/// form, non-minimal integers, trailing bytes, oversized values) → None.
pub fn parse_der_signature(der: &[u8]) -> Option<[u8; 64]> {
    fn parse_integer<'a>(rest: &'a [u8], out: &mut [u8]) -> Option<&'a [u8]> {
        let [0x02, len, body @ ..] = rest else { return None };
        let len = *len as usize;
        // Short-form length only (valid r/s never need long form), and
        // a non-empty, non-negative, minimally-encoded integer.
        if len == 0 || len >= 0x80 || body.len() < len {
            return None;
        }
        let (value, rest) = body.split_at(len);
        if value[0] & 0x80 != 0 {
            return None; // negative
        }
        if len > 1 && value[0] == 0 && value[1] & 0x80 == 0 {
            return None; // non-minimal leading zero
        }
        let value = if value[0] == 0 { &value[1..] } else { value };
        if value.len() > 32 {
            return None; // exceeds field width
        }
        out[32 - value.len()..].copy_from_slice(value);
        Some(rest)
    }

    let [0x30, len, body @ ..] = der else { return None };
    if *len as usize != body.len() || *len >= 0x80 {
        return None;
    }
    let mut sig = [0u8; 64];
    let rest = parse_integer(body, &mut sig[0..32])?;
    let rest = parse_integer(rest, &mut sig[32..64])?;
    rest.is_empty().then_some(sig)
}

/// EVM `getData` semantics: take `len` bytes from `offset`, zero-padding
/// on the right past the end of `input`.
pub fn get_data(input: &[u8], offset: usize, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    if offset < input.len() {
        let n = core::cmp::min(len, input.len() - offset);
        out[..n].copy_from_slice(&input[offset..offset + n]);
    }
    out
}

/// 32-byte big-endian word with `v` in the low 8 bytes.
pub fn be_word(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&v.to_be_bytes());
    out
}

// ---------------------------------------------------------------------
// EIP-2537 wire format ↔ zkvm_accelerators.h ABI
//
// Wire (EIP-2537):  Fp = 64 bytes BE, top 16 required zero.
//                   G1 = x(64) || y(64); G2 = x_c0 || x_c1 || y_c0 || y_c1.
//                   Infinity = all-zero bytes.
// ABI (this SDK):   Fp = 48 bytes BE.
//                   G1 = x || y; G2 = x_c1 || x_c0 || y_c1 || y_c0.
//                   Infinity = 0x40 flag bit in the leading byte,
//                   zero coordinates (zkcrypto uncompressed form).
// ---------------------------------------------------------------------

/// Strip the 16-byte zero padding from a 64-byte wire Fp; `None` if the
/// padding is non-zero (EIP-2537 requires rejecting such inputs).
pub fn unpad_fp(b: &[u8]) -> Option<[u8; 48]> {
    assert_eq!(b.len(), 64);
    if b[..16].iter().any(|&x| x != 0) {
        return None;
    }
    Some(b[16..64].try_into().unwrap())
}

fn pad_fp(b: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[16..].copy_from_slice(b);
    out
}

/// 128-byte wire G1 → 96-byte ABI G1.
pub fn wire_g1_to_abi(b: &[u8]) -> Option<[u8; 96]> {
    assert_eq!(b.len(), 128);
    let mut out = [0u8; 96];
    if b.iter().all(|&x| x == 0) {
        out[0] = 0x40; // point at infinity
        return Some(out);
    }
    out[0..48].copy_from_slice(&unpad_fp(&b[0..64])?);
    out[48..96].copy_from_slice(&unpad_fp(&b[64..128])?);
    Some(out)
}

/// 96-byte ABI G1 → 128-byte wire G1.
pub fn abi_g1_to_wire(b: &[u8; 96]) -> [u8; 128] {
    let mut out = [0u8; 128];
    if b[0] & 0x40 != 0 {
        return out; // infinity → all zeros
    }
    out[0..64].copy_from_slice(&pad_fp(&b[0..48]));
    out[64..128].copy_from_slice(&pad_fp(&b[48..96]));
    out
}

/// 256-byte wire G2 → 192-byte ABI G2 (coefficient order swap).
pub fn wire_g2_to_abi(b: &[u8]) -> Option<[u8; 192]> {
    assert_eq!(b.len(), 256);
    let mut out = [0u8; 192];
    if b.iter().all(|&x| x == 0) {
        out[0] = 0x40;
        return Some(out);
    }
    // wire: x_c0 || x_c1 || y_c0 || y_c1   (64 bytes each)
    // abi:  x_c1 || x_c0 || y_c1 || y_c0   (48 bytes each)
    out[0..48].copy_from_slice(&unpad_fp(&b[64..128])?); // x_c1
    out[48..96].copy_from_slice(&unpad_fp(&b[0..64])?); // x_c0
    out[96..144].copy_from_slice(&unpad_fp(&b[192..256])?); // y_c1
    out[144..192].copy_from_slice(&unpad_fp(&b[128..192])?); // y_c0
    Some(out)
}

/// 192-byte ABI G2 → 256-byte wire G2.
pub fn abi_g2_to_wire(b: &[u8; 192]) -> [u8; 256] {
    let mut out = [0u8; 256];
    if b[0] & 0x40 != 0 {
        return out;
    }
    out[0..64].copy_from_slice(&pad_fp(&b[48..96])); // x_c0
    out[64..128].copy_from_slice(&pad_fp(&b[0..48])); // x_c1
    out[128..192].copy_from_slice(&pad_fp(&b[144..192])); // y_c0
    out[192..256].copy_from_slice(&pad_fp(&b[96..144])); // y_c1
    out
}
