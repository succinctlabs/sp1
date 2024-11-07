use std::{fs::File, io::Write};

use p3_field::{AbstractExtensionField, AbstractField, PrimeField};
use serde::{Deserialize, Serialize};
use sp1_recursion_compiler::ir::{Config, Witness};

/// A witness that can be used to initialize values for witness generation inside Gnark.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GnarkWitness {
    pub vars: Vec<String>,
    pub felts: Vec<String>,
    pub exts: Vec<Vec<String>>,
    pub vkey_hash: String,
    pub committed_values_digest: String,
}

impl GnarkWitness {
    /// Creates a new witness from a given [Witness].
    pub fn new<C: Config>(mut witness: Witness<C>) -> Self {
        witness.vars.push(C::N::from_canonical_usize(999));
        witness.felts.push(C::F::from_canonical_usize(999));
        witness.exts.push(C::EF::from_canonical_usize(999));
        GnarkWitness {
            vars: witness.vars.into_iter().map(|w| w.as_canonical_biguint().to_string()).collect(),
            felts: witness
                .felts
                .into_iter()
                .map(|w| w.as_canonical_biguint().to_string())
                .collect(),
            exts: witness
                .exts
                .into_iter()
                .map(|w| {
                    w.as_base_slice().iter().map(|x| x.as_canonical_biguint().to_string()).collect()
                })
                .collect(),
            vkey_hash: witness.vkey_hash.as_canonical_biguint().to_string(),
            committed_values_digest: witness
                .committed_values_digest
                .as_canonical_biguint()
                .to_string(),
        }
    }

    /// Saves the witness to a given path.
    pub fn save(&self, path: &str) {
        let serialized = serde_json::to_string(self).unwrap();
        let mut file = File::create(path).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();
    }
}
