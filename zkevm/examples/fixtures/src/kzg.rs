//! KZG point-evaluation test vectors from the Ethereum consensus-specs
//! suite (`verify_kzg_proof_case_*`).
//!
//! The vectors are baked in via `include_str!` and parsed lazily on
//! demand. Each case has one of three shapes:
//!
//! - `output: true`  — input is well-formed and the opening verifies.
//! - `output: false` — input is well-formed but the proof is wrong.
//! - `output: null`  — at least one of `commitment`/`z`/`y`/`proof` is
//!   not a valid encoding (sub-group / range checks fail).
//!
//! `Expected::from_yaml` collapses the third case into "verified =
//! false", which matches `zkvm_kzg_point_eval`'s contract: parse errors
//! and pairing-check failures both produce `*verified = false`, only
//! null pointers surface as `ZKVM_EFAIL`.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct RawInput {
    commitment: String,
    z: String,
    y: String,
    proof: String,
}

#[derive(Debug, Deserialize)]
struct Raw {
    input: RawInput,
    output: Option<bool>,
}

/// One parsed KZG verify_kzg_proof test case.
#[derive(Debug)]
pub struct Vector {
    pub name: &'static str,
    pub commitment: Vec<u8>,
    pub z: Vec<u8>,
    pub y: Vec<u8>,
    pub proof: Vec<u8>,
    /// `true`/`false` if the spec lists a definite outcome; `false` if
    /// the spec says `null` (invalid input — we conservatively expect
    /// the guest to also report unverified).
    pub expected_verified: bool,
    /// `true` iff the spec reports `output: null` (encoding-invalid).
    pub is_invalid_input: bool,
}

impl Vector {
    /// True iff every input is the byte length our C ABI expects
    /// (commitment/proof = 48, z/y = 32). The consensus-specs `invalid_*`
    /// cases include cases that test wire-format validation, where an
    /// input has the wrong length — those are rejected at the C ABI
    /// boundary before libzkevm sees them, so callers may want to skip
    /// running them through the guest.
    pub fn has_canonical_lengths(&self) -> bool {
        self.commitment.len() == 48
            && self.z.len() == 32
            && self.y.len() == 32
            && self.proof.len() == 48
    }
}

struct Source {
    name: &'static str,
    yaml: &'static str,
}

const SOURCES: &[Source] = &[
    Source {
        name: "correct_02e696",
        yaml: include_str!("../data/kzg/correct_proof_02e696ada7d4631d.yaml"),
    },
    Source {
        name: "correct_05c1f3",
        yaml: include_str!("../data/kzg/correct_proof_05c1f3685f3393f0.yaml"),
    },
    Source {
        name: "correct_08f9e2",
        yaml: include_str!("../data/kzg/correct_proof_08f9e2f1cb3d39db.yaml"),
    },
    Source {
        name: "correct_0cf79b",
        yaml: include_str!("../data/kzg/correct_proof_0cf79b17cb5f4ea2.yaml"),
    },
    Source {
        name: "incorrect_02e696",
        yaml: include_str!("../data/kzg/incorrect_proof_02e696ada7d4631d.yaml"),
    },
    Source {
        name: "incorrect_05c1f3",
        yaml: include_str!("../data/kzg/incorrect_proof_05c1f3685f3393f0.yaml"),
    },
    Source {
        name: "incorrect_08f9e2",
        yaml: include_str!("../data/kzg/incorrect_proof_08f9e2f1cb3d39db.yaml"),
    },
    Source {
        name: "incorrect_0cf79b",
        yaml: include_str!("../data/kzg/incorrect_proof_0cf79b17cb5f4ea2.yaml"),
    },
    Source {
        name: "invalid_commitment_1b44e3",
        yaml: include_str!("../data/kzg/invalid_commitment_1b44e341d56c757d.yaml"),
    },
    Source {
        name: "invalid_proof_1b44e3",
        yaml: include_str!("../data/kzg/invalid_proof_1b44e341d56c757d.yaml"),
    },
    Source {
        name: "invalid_z_35d08d",
        yaml: include_str!("../data/kzg/invalid_z_35d08d612aad2197.yaml"),
    },
    Source {
        name: "invalid_y_35d08d",
        yaml: include_str!("../data/kzg/invalid_y_35d08d612aad2197.yaml"),
    },
];

fn decode_hex(s: &str) -> Vec<u8> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(trimmed).expect("test vector hex")
}

/// Iterate over all bundled `verify_kzg_proof` cases.
pub fn vectors() -> impl Iterator<Item = Vector> {
    SOURCES.iter().map(|src| {
        let raw: Raw = serde_yaml::from_str(src.yaml).expect("kzg fixture parses");
        let (expected_verified, is_invalid_input) = match raw.output {
            Some(b) => (b, false),
            None => (false, true),
        };
        Vector {
            name: src.name,
            commitment: decode_hex(&raw.input.commitment),
            z: decode_hex(&raw.input.z),
            y: decode_hex(&raw.input.y),
            proof: decode_hex(&raw.input.proof),
            expected_verified,
            is_invalid_input,
        }
    })
}
