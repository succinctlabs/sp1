//! Batch wire format shared by the conformance guest and its host
//! script (both `#[path]`-include this file; keep it dependency-free
//! and `no_std`-clean).
//!
//! ```text
//! batch := case* END
//! case  := op:u8 expect_fail:u8 input_len:u32le input expected_len:u32le expected
//! ```
//!
//! Inputs are in the C-ABI encoding (the host converts from EVM wire
//! format) — the guest exercises the accelerator implementations over
//! the real syscalls, not the wire glue (host tests cover that).
//!
//! Per-op input/expected layouts (sizes in bytes):
//!
//! | op | accelerator              | input                                  | expected |
//! |----|--------------------------|----------------------------------------|----------|
//! | 1  | bls12_g1_add             | 96 + 96                                | 96       |
//! | 2  | bls12_g2_add             | 192 + 192                              | 192      |
//! | 3  | bls12_g1_msm             | n × (96 + 32)                          | 96       |
//! | 4  | bls12_g2_msm             | n × (192 + 32)                         | 192      |
//! | 5  | bls12_pairing            | n × (96 + 192)                         | 1        |
//! | 6  | bls12_map_fp_to_g1       | 48                                     | 96       |
//! | 7  | bls12_map_fp2_to_g2      | 96                                     | 192      |
//! | 8  | bn254_g1_add             | 64 + 64                                | 64       |
//! | 9  | bn254_g1_mul             | 64 + 32                                | 64       |
//! | 10 | bn254_pairing            | n × (64 + 128)                         | 1        |
//! | 11 | secp256k1_ecrecover      | 32 msg + 64 sig + 1 recid              | 64       |
//! | 12 | secp256k1_verify         | 32 msg + 64 sig + 64 pubkey            | 1        |
//! | 13 | secp256r1_verify         | 32 msg + 64 sig + 64 pubkey            | 1        |
//! | 14 | modexp                   | 3 × u32le lens + base + exp + mod      | mod_len  |
//! | 15 | blake2f                  | u32le rounds + 64 h + 128 m + 16 t + 1 f | 64     |
//! | 16 | kzg_point_eval           | 48 c + 32 z + 32 y + 48 proof          | 1        |
//!
//! `expect_fail = 1` means the accelerator must return `ZKVM_EFAIL`
//! (`expected_len` is 0). For the bool-output ops (5, 10, 12, 13, 16)
//! a *failed check* is `expected = [0]` with `expect_fail = 0`;
//! `expect_fail = 1` is reserved for malformed-input rejection.

pub const OP_G1_ADD: u8 = 1;
pub const OP_G2_ADD: u8 = 2;
pub const OP_G1_MSM: u8 = 3;
pub const OP_G2_MSM: u8 = 4;
pub const OP_BLS_PAIRING: u8 = 5;
pub const OP_MAP_FP_G1: u8 = 6;
pub const OP_MAP_FP2_G2: u8 = 7;
pub const OP_BN_ADD: u8 = 8;
pub const OP_BN_MUL: u8 = 9;
pub const OP_BN_PAIRING: u8 = 10;
pub const OP_ECRECOVER: u8 = 11;
pub const OP_K1_VERIFY: u8 = 12;
pub const OP_R1_VERIFY: u8 = 13;
pub const OP_MODEXP: u8 = 14;
pub const OP_BLAKE2F: u8 = 15;
pub const OP_KZG_POINT_EVAL: u8 = 16;
pub const OP_END: u8 = 0xFF;

/// Cap on reported failing cases in the guest's committed summary.
pub const MAX_REPORTED_FAILURES: usize = 16;
