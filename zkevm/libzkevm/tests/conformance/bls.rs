//! EIP-2537 conformance (precompiles 0x0b–0x11) against the full
//! go-ethereum vector suites, success and `fail-*` rejection cases.
//!
//! Each `run_*` function is the EVM-glue for one precompile: wire-format
//! validation + conversion, the C-ABI call, and output re-encoding.
//! `None` means "precompile errors" (consumes all gas in the EVM); the
//! rejection vectors must all land there, whether the converter or the
//! ABI function rejects.

use crate::support::*;
use crate::{EFAIL, EOK};
use zkevm::precompile::bls12_381::*;
use zkevm::precompile::types::*;

fn run_g1_add(input: &[u8]) -> Option<Vec<u8>> {
    if input.len() != 256 {
        return None;
    }
    let p1 = ZkvmBytes96 { data: wire_g1_to_abi(&input[0..128])? };
    let p2 = ZkvmBytes96 { data: wire_g1_to_abi(&input[128..256])? };
    let mut out = ZkvmBytes96 { data: [0u8; 96] };
    let status = unsafe { zkvm_bls12_g1_add(&p1, &p2, &mut out) };
    (status == EOK).then(|| abi_g1_to_wire(&out.data).to_vec())
}

fn run_g1_msm(input: &[u8]) -> Option<Vec<u8>> {
    if input.is_empty() || !input.len().is_multiple_of(160) {
        return None;
    }
    let mut pairs = Vec::with_capacity(input.len() / 160);
    for chunk in input.chunks_exact(160) {
        pairs.push(Bls12381G1MsmPair {
            point: ZkvmBytes96 { data: wire_g1_to_abi(&chunk[0..128])? },
            scalar: ZkvmBytes32 { data: chunk[128..160].try_into().unwrap() },
        });
    }
    let mut out = ZkvmBytes96 { data: [0u8; 96] };
    let status = unsafe { zkvm_bls12_g1_msm(pairs.as_ptr(), pairs.len(), &mut out) };
    (status == EOK).then(|| abi_g1_to_wire(&out.data).to_vec())
}

fn run_g2_add(input: &[u8]) -> Option<Vec<u8>> {
    if input.len() != 512 {
        return None;
    }
    let p1 = ZkvmBytes192 { data: wire_g2_to_abi(&input[0..256])? };
    let p2 = ZkvmBytes192 { data: wire_g2_to_abi(&input[256..512])? };
    let mut out = ZkvmBytes192 { data: [0u8; 192] };
    let status = unsafe { zkvm_bls12_g2_add(&p1, &p2, &mut out) };
    (status == EOK).then(|| abi_g2_to_wire(&out.data).to_vec())
}

fn run_g2_msm(input: &[u8]) -> Option<Vec<u8>> {
    if input.is_empty() || !input.len().is_multiple_of(288) {
        return None;
    }
    let mut pairs = Vec::with_capacity(input.len() / 288);
    for chunk in input.chunks_exact(288) {
        pairs.push(Bls12381G2MsmPair {
            point: ZkvmBytes192 { data: wire_g2_to_abi(&chunk[0..256])? },
            scalar: ZkvmBytes32 { data: chunk[256..288].try_into().unwrap() },
        });
    }
    let mut out = ZkvmBytes192 { data: [0u8; 192] };
    let status = unsafe { zkvm_bls12_g2_msm(pairs.as_ptr(), pairs.len(), &mut out) };
    (status == EOK).then(|| abi_g2_to_wire(&out.data).to_vec())
}

fn run_pairing(input: &[u8]) -> Option<Vec<u8>> {
    if input.is_empty() || !input.len().is_multiple_of(384) {
        return None;
    }
    let mut pairs = Vec::with_capacity(input.len() / 384);
    for chunk in input.chunks_exact(384) {
        pairs.push(Bls12381PairingPair {
            g1: ZkvmBytes96 { data: wire_g1_to_abi(&chunk[0..128])? },
            g2: ZkvmBytes192 { data: wire_g2_to_abi(&chunk[128..384])? },
        });
    }
    let mut verified = false;
    let status = unsafe { zkvm_bls12_pairing(pairs.as_ptr(), pairs.len(), &mut verified) };
    (status == EOK).then(|| be_word(verified as u64).to_vec())
}

fn run_map_fp_to_g1(input: &[u8]) -> Option<Vec<u8>> {
    if input.len() != 64 {
        return None;
    }
    let fp = ZkvmBytes48 { data: unpad_fp(input)? };
    let mut out = ZkvmBytes96 { data: [0u8; 96] };
    let status = unsafe { zkvm_bls12_map_fp_to_g1(&fp, &mut out) };
    (status == EOK).then(|| abi_g1_to_wire(&out.data).to_vec())
}

fn run_map_fp2_to_g2(input: &[u8]) -> Option<Vec<u8>> {
    if input.len() != 128 {
        return None;
    }
    // wire: c0(64) || c1(64); ABI Fp2: c1(48) || c0(48).
    let mut data = [0u8; 96];
    data[0..48].copy_from_slice(&unpad_fp(&input[64..128])?);
    data[48..96].copy_from_slice(&unpad_fp(&input[0..64])?);
    let fp2 = ZkvmBytes96 { data };
    let mut out = ZkvmBytes192 { data: [0u8; 192] };
    let status = unsafe { zkvm_bls12_map_fp2_to_g2(&fp2, &mut out) };
    (status == EOK).then(|| abi_g2_to_wire(&out.data).to_vec())
}

/// Run every success vector in `file` and every rejection vector in
/// `fail_file` through `run`.
fn conformance(file: &str, fail_file: &str, run: impl Fn(&[u8]) -> Option<Vec<u8>>) {
    for v in load_geth(file) {
        let expected =
            unhex(v.expected.as_ref().unwrap_or_else(|| panic!("{}: no Expected", v.name)));
        let got = run(&unhex(&v.input))
            .unwrap_or_else(|| panic!("{file}/{}: rejected a valid input", v.name));
        assert_eq!(got, expected, "{file}/{}", v.name);
    }
    for v in load_geth(fail_file) {
        assert!(
            run(&unhex(&v.input)).is_none(),
            "{fail_file}/{}: accepted an invalid input (expected: {})",
            v.name,
            v.expected_error.as_deref().unwrap_or("?")
        );
    }
}

#[test]
fn bls_g1_add() {
    conformance("blsG1Add", "fail-blsG1Add", run_g1_add);
}

#[test]
fn bls_g1_mul() {
    // The dedicated MUL precompile was folded into MSM in the final
    // EIP-2537; the vectors remain valid single-pair MSM cases.
    conformance("blsG1Mul", "fail-blsG1Mul", run_g1_msm);
}

#[test]
fn bls_g1_msm() {
    conformance("blsG1MultiExp", "fail-blsG1MultiExp", run_g1_msm);
}

#[test]
fn bls_g2_add() {
    conformance("blsG2Add", "fail-blsG2Add", run_g2_add);
}

#[test]
fn bls_g2_mul() {
    conformance("blsG2Mul", "fail-blsG2Mul", run_g2_msm);
}

#[test]
fn bls_g2_msm() {
    conformance("blsG2MultiExp", "fail-blsG2MultiExp", run_g2_msm);
}

#[test]
fn bls_pairing() {
    conformance("blsPairing", "fail-blsPairing", run_pairing);
}

#[test]
fn bls_map_fp_to_g1() {
    conformance("blsMapG1", "fail-blsMapG1", run_map_fp_to_g1);
}

#[test]
fn bls_map_fp2_to_g2() {
    conformance("blsMapG2", "fail-blsMapG2", run_map_fp2_to_g2);
}

/// The EFAIL constant in this harness must match the crate's. Pin it via
/// a call that is unambiguously API misuse (null output pointer).
#[test]
fn efail_matches_abi() {
    let p = ZkvmBytes96 { data: [0u8; 96] };
    let status = unsafe { zkvm_bls12_g1_add(&p, &p, core::ptr::null_mut()) };
    assert_eq!(status, EFAIL);
}
