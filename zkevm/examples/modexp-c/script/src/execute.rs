//! Execute modexp-c against host-side modexp on EIP-198 test vectors.

use num_bigint::BigUint;
use sp1_sdk::{utils, Elf, Prover, ProverClient, SP1Stdin};
use tracing::info;

const ELF_BYTES: &[u8] = include_bytes!(env!("MODEXP_C_ELF"));
const ELF: Elf = Elf::Static(ELF_BYTES);

fn build_input(base: &[u8], exp: &[u8], modulus: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(12 + base.len() + exp.len() + modulus.len());
    buf.extend_from_slice(&(base.len() as u32).to_be_bytes());
    buf.extend_from_slice(&(exp.len() as u32).to_be_bytes());
    buf.extend_from_slice(&(modulus.len() as u32).to_be_bytes());
    buf.extend_from_slice(base);
    buf.extend_from_slice(exp);
    buf.extend_from_slice(modulus);
    buf
}

fn host_modexp(base: &[u8], exp: &[u8], modulus: &[u8]) -> Vec<u8> {
    let mod_len = modulus.len();
    if mod_len == 0 {
        return Vec::new();
    }
    let m = BigUint::from_bytes_be(modulus);
    if m == BigUint::default() {
        return vec![0u8; mod_len];
    }
    let b = BigUint::from_bytes_be(base);
    let e = BigUint::from_bytes_be(exp);
    let r = b.modpow(&e, &m).to_bytes_be();
    let mut out = vec![0u8; mod_len];
    let off = mod_len - r.len();
    out[off..].copy_from_slice(&r);
    out
}

#[tokio::main]
async fn main() {
    utils::setup_logger();

    let client = ProverClient::builder().light().build().await;

    // EIP-198 example 1: 3^65537 mod a 1024-bit prime (≈Fermat-style RSA).
    //   p (32 bytes) for compactness; canonical EIP-198 uses 1024-bit p.
    let base_a = vec![3u8];
    let exp_a = 65537u32.to_be_bytes().to_vec();
    let mod_a = hex::decode(
        "fffffffffffffffffffffffffffffffefffffffffffffffe\
         ffffffffffffffffffffffffffffffff",
    )
    .unwrap();

    // Edge cases.
    let base_b = vec![0u8]; // 0^x mod m = 0 (for x ≥ 1)
    let exp_b = vec![5u8];
    let mod_b = vec![0xff, 0xff];

    let base_c = vec![5u8]; // x^0 mod m = 1
    let exp_c = vec![0u8];
    let mod_c = vec![0x10, 0x00];

    let base_d = vec![5u8]; // mod 1 -> 0
    let exp_d = vec![3u8];
    let mod_d = vec![1u8];

    for (label, base, exp, modulus) in [
        ("3^65537 mod p256", &base_a[..], &exp_a[..], &mod_a[..]),
        ("0^5 mod 0xffff", &base_b[..], &exp_b[..], &mod_b[..]),
        ("5^0 mod 0x1000", &base_c[..], &exp_c[..], &mod_c[..]),
        ("5^3 mod 1", &base_d[..], &exp_d[..], &mod_d[..]),
    ] {
        let input = build_input(base, exp, modulus);
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);
        let (public_values, report) = client.execute(ELF, stdin).await.unwrap();
        let out = public_values.as_slice();
        let expected = host_modexp(base, exp, modulus);
        info!(
            label = label,
            cycles = report.total_instruction_count() + report.total_syscall_count(),
            "executed modexp-c",
        );
        assert_eq!(out, expected.as_slice(), "{label} mismatch");
    }

    info!("all modexp-c outputs match host-computed values");

    // ---- EIP-198 golden vectors (explicit known-answer pairs). Catches
    //      regressions in the I/O contract (output length = mod_len,
    //      left zero-padding, modulus == 0 behavior) that random
    //      differential checks against `BigUint::modpow` would silently
    //      satisfy if both sides shared the same bug.
    for v in zkevm_fixtures::eip198::vectors() {
        let input = build_input(&v.base, &v.exp, &v.modulus);
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);
        let (public_values, report) = client.execute(ELF, stdin).await.unwrap();
        let out = public_values.as_slice();
        info!(
            name = v.name.as_str(),
            mod_len = v.modulus.len(),
            cycles = report.total_instruction_count() + report.total_syscall_count(),
            "executed modexp-c (eip-198 vector)",
        );
        assert_eq!(out, v.expected.as_slice(), "{}: guest output != expected", v.name);
    }

    info!("all eip-198 golden vectors match the guest output");
}
