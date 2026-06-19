//! conformance — batched executor conformance guest.
//!
//! Reads one serialized batch (format: see `../../ops.rs`) from stdin,
//! runs every case through the libzkevm accelerator C ABI — i.e. the
//! real SP1 syscall paths at `target_os = "zkvm"` — and commits:
//!
//! ```text
//! total:u32le failures:u32le (case_index:u32le op:u8) × min(failures, 16)
//! ```
//!
//! The host script builds the batch from the official vector suites and
//! asserts `failures == 0`.

#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use zkevm::precompile::types::*;
use zkevm::precompile::{blake2f, bls12_381, bn254, kzg, modexp, secp256k1, secp256r1};

#[path = "../../ops.rs"]
mod ops;
use ops::*;

zkevm::entrypoint!(main);

const EOK: i32 = 0;

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> u8 {
        let v = self.buf[self.pos];
        self.pos += 1;
        v
    }

    fn u32(&mut self) -> u32 {
        let v = u32::from_le_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        v
    }

    fn bytes(&mut self, n: usize) -> &'a [u8] {
        let v = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        v
    }
}

fn arr<const N: usize>(b: &[u8]) -> [u8; N] {
    b.try_into().expect("malformed batch: wrong field size")
}

/// Run one case; `None` = the accelerator returned `ZKVM_EFAIL`.
fn run_case(op: u8, input: &[u8]) -> Option<Vec<u8>> {
    match op {
        OP_G1_ADD => {
            let p1 = ZkvmBytes96 { data: arr(&input[0..96]) };
            let p2 = ZkvmBytes96 { data: arr(&input[96..192]) };
            let mut out = ZkvmBytes96 { data: [0u8; 96] };
            let status = unsafe { bls12_381::zkvm_bls12_g1_add(&p1, &p2, &mut out) };
            (status == EOK).then(|| out.data.to_vec())
        }
        OP_G2_ADD => {
            let p1 = ZkvmBytes192 { data: arr(&input[0..192]) };
            let p2 = ZkvmBytes192 { data: arr(&input[192..384]) };
            let mut out = ZkvmBytes192 { data: [0u8; 192] };
            let status = unsafe { bls12_381::zkvm_bls12_g2_add(&p1, &p2, &mut out) };
            (status == EOK).then(|| out.data.to_vec())
        }
        OP_G1_MSM => {
            let pairs: Vec<Bls12381G1MsmPair> = input
                .chunks_exact(128)
                .map(|c| Bls12381G1MsmPair {
                    point: ZkvmBytes96 { data: arr(&c[0..96]) },
                    scalar: ZkvmBytes32 { data: arr(&c[96..128]) },
                })
                .collect();
            let mut out = ZkvmBytes96 { data: [0u8; 96] };
            let status =
                unsafe { bls12_381::zkvm_bls12_g1_msm(pairs.as_ptr(), pairs.len(), &mut out) };
            (status == EOK).then(|| out.data.to_vec())
        }
        OP_G2_MSM => {
            let pairs: Vec<Bls12381G2MsmPair> = input
                .chunks_exact(224)
                .map(|c| Bls12381G2MsmPair {
                    point: ZkvmBytes192 { data: arr(&c[0..192]) },
                    scalar: ZkvmBytes32 { data: arr(&c[192..224]) },
                })
                .collect();
            let mut out = ZkvmBytes192 { data: [0u8; 192] };
            let status =
                unsafe { bls12_381::zkvm_bls12_g2_msm(pairs.as_ptr(), pairs.len(), &mut out) };
            (status == EOK).then(|| out.data.to_vec())
        }
        OP_BLS_PAIRING => {
            let pairs: Vec<Bls12381PairingPair> = input
                .chunks_exact(288)
                .map(|c| Bls12381PairingPair {
                    g1: ZkvmBytes96 { data: arr(&c[0..96]) },
                    g2: ZkvmBytes192 { data: arr(&c[96..288]) },
                })
                .collect();
            let mut verified = false;
            let status = unsafe {
                bls12_381::zkvm_bls12_pairing(pairs.as_ptr(), pairs.len(), &mut verified)
            };
            (status == EOK).then(|| alloc::vec![verified as u8])
        }
        OP_MAP_FP_G1 => {
            let fp = ZkvmBytes48 { data: arr(input) };
            let mut out = ZkvmBytes96 { data: [0u8; 96] };
            let status = unsafe { bls12_381::zkvm_bls12_map_fp_to_g1(&fp, &mut out) };
            (status == EOK).then(|| out.data.to_vec())
        }
        OP_MAP_FP2_G2 => {
            let fp2 = ZkvmBytes96 { data: arr(input) };
            let mut out = ZkvmBytes192 { data: [0u8; 192] };
            let status = unsafe { bls12_381::zkvm_bls12_map_fp2_to_g2(&fp2, &mut out) };
            (status == EOK).then(|| out.data.to_vec())
        }
        OP_BN_ADD => {
            let p1 = ZkvmBytes64 { data: arr(&input[0..64]) };
            let p2 = ZkvmBytes64 { data: arr(&input[64..128]) };
            let mut out = ZkvmBytes64 { data: [0u8; 64] };
            let status = unsafe { bn254::zkvm_bn254_g1_add(&p1, &p2, &mut out) };
            (status == EOK).then(|| out.data.to_vec())
        }
        OP_BN_MUL => {
            let p = ZkvmBytes64 { data: arr(&input[0..64]) };
            let s = ZkvmBytes32 { data: arr(&input[64..96]) };
            let mut out = ZkvmBytes64 { data: [0u8; 64] };
            let status = unsafe { bn254::zkvm_bn254_g1_mul(&p, &s, &mut out) };
            (status == EOK).then(|| out.data.to_vec())
        }
        OP_BN_PAIRING => {
            let pairs: Vec<Bn254PairingPair> = input
                .chunks_exact(192)
                .map(|c| Bn254PairingPair {
                    g1: ZkvmBytes64 { data: arr(&c[0..64]) },
                    g2: ZkvmBytes128 { data: arr(&c[64..192]) },
                })
                .collect();
            let mut verified = false;
            let status =
                unsafe { bn254::zkvm_bn254_pairing(pairs.as_ptr(), pairs.len(), &mut verified) };
            (status == EOK).then(|| alloc::vec![verified as u8])
        }
        OP_ECRECOVER => {
            let msg = ZkvmBytes32 { data: arr(&input[0..32]) };
            let sig = ZkvmBytes64 { data: arr(&input[32..96]) };
            let recid = input[96];
            let mut out = ZkvmBytes64 { data: [0u8; 64] };
            let status =
                unsafe { secp256k1::zkvm_secp256k1_ecrecover(&msg, &sig, recid, &mut out) };
            (status == EOK).then(|| out.data.to_vec())
        }
        OP_K1_VERIFY | OP_R1_VERIFY => {
            let msg = ZkvmBytes32 { data: arr(&input[0..32]) };
            let sig = ZkvmBytes64 { data: arr(&input[32..96]) };
            let pubkey = ZkvmBytes64 { data: arr(&input[96..160]) };
            let mut verified = false;
            let status = unsafe {
                if op == OP_K1_VERIFY {
                    secp256k1::zkvm_secp256k1_verify(&msg, &sig, &pubkey, &mut verified)
                } else {
                    secp256r1::zkvm_secp256r1_verify(&msg, &sig, &pubkey, &mut verified)
                }
            };
            (status == EOK).then(|| alloc::vec![verified as u8])
        }
        OP_MODEXP => {
            let base_len = u32::from_le_bytes(arr(&input[0..4])) as usize;
            let exp_len = u32::from_le_bytes(arr(&input[4..8])) as usize;
            let mod_len = u32::from_le_bytes(arr(&input[8..12])) as usize;
            let base = &input[12..12 + base_len];
            let exp = &input[12 + base_len..12 + base_len + exp_len];
            let modulus = &input[12 + base_len + exp_len..12 + base_len + exp_len + mod_len];
            let mut out = alloc::vec![0u8; mod_len];
            let status = unsafe {
                modexp::zkvm_modexp(
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
        OP_BLAKE2F => {
            let rounds = u32::from_le_bytes(arr(&input[0..4]));
            let mut h = ZkvmBytes64 { data: arr(&input[4..68]) };
            let m = ZkvmBytes128 { data: arr(&input[68..196]) };
            let t = ZkvmBytes16 { data: arr(&input[196..212]) };
            let f = input[212];
            let status = unsafe { blake2f::zkvm_blake2f(rounds, &mut h, &m, &t, f) };
            (status == EOK).then(|| h.data.to_vec())
        }
        OP_KZG_POINT_EVAL => {
            let commitment = ZkvmBytes48 { data: arr(&input[0..48]) };
            let z = ZkvmBytes32 { data: arr(&input[48..80]) };
            let y = ZkvmBytes32 { data: arr(&input[80..112]) };
            let proof = ZkvmBytes48 { data: arr(&input[112..160]) };
            let mut verified = false;
            let status =
                unsafe { kzg::zkvm_kzg_point_eval(&commitment, &z, &y, &proof, &mut verified) };
            (status == EOK).then(|| alloc::vec![verified as u8])
        }
        other => panic!("malformed batch: unknown op {other}"),
    }
}

pub fn main() {
    let mut buf_ptr: *const u8 = core::ptr::null();
    let mut buf_size: usize = 0;
    unsafe {
        zkevm::io::read_input(&mut buf_ptr, &mut buf_size);
    }
    let batch = unsafe { core::slice::from_raw_parts(buf_ptr, buf_size) };
    let mut reader = Reader { buf: batch, pos: 0 };

    let mut total: u32 = 0;
    let mut fail_total: u32 = 0;
    let mut failed: Vec<(u32, u8)> = Vec::new();

    loop {
        let op = reader.u8();
        if op == OP_END {
            break;
        }
        let expect_fail = reader.u8();
        let input_len = reader.u32() as usize;
        let input = reader.bytes(input_len);
        let expected_len = reader.u32() as usize;
        let expected = reader.bytes(expected_len);

        let pass = match run_case(op, input) {
            None => expect_fail == 1,
            Some(out) => expect_fail == 0 && out == expected,
        };
        if !pass {
            fail_total += 1;
            if failed.len() < MAX_REPORTED_FAILURES {
                failed.push((total, op));
            }
        }
        total += 1;
    }

    // Summary: total, failure count, then the first reported failures.
    let mut summary = Vec::with_capacity(8 + failed.len() * 5);
    summary.extend_from_slice(&total.to_le_bytes());
    summary.extend_from_slice(&fail_total.to_le_bytes());
    for (index, op) in &failed {
        summary.extend_from_slice(&index.to_le_bytes());
        summary.push(*op);
    }
    unsafe {
        zkevm::io::write_output(summary.as_ptr(), summary.len());
    }
}
