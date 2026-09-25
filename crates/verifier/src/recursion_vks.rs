use serde::{Deserialize, Serialize};
use slop_challenger::IopCtx;
use sp1_hypercube::{verify_merkle_proof, HashableKey, MachineVerifyingKey, MerkleProof};
use sp1_primitives::SP1GlobalContext;

/// The serialized recursion verifying key data for this SP1 version.
const VERIFIER_VK_DATA_BYTES: &[u8] = include_bytes!("../vk-artifacts/verifier_vks.bin");

#[derive(Clone, Serialize, Debug, PartialEq, Eq, Deserialize)]
pub struct VerifierRecursionVks {
    pub root: <SP1GlobalContext as IopCtx>::Digest,
    pub vk_verification: bool,
    pub num_keys: usize,
}

impl Default for VerifierRecursionVks {
    fn default() -> Self {
        bincode::deserialize(VERIFIER_VK_DATA_BYTES).unwrap()
    }
}

impl VerifierRecursionVks {
    pub fn vk_verification(&self) -> bool {
        self.vk_verification
    }

    pub fn root(&self) -> <SP1GlobalContext as IopCtx>::Digest {
        self.root
    }

    pub fn num_keys(&self) -> usize {
        self.num_keys
    }

    pub fn verify(
        &self,
        proof: &MerkleProof<SP1GlobalContext>,
        vk: &MachineVerifyingKey<SP1GlobalContext>,
    ) -> bool {
        if !self.vk_verification {
            return true;
        }
        if self.num_keys == 0 {
            return false;
        }
        let Some(tree_size) = self.num_keys.checked_next_power_of_two() else {
            return false;
        };
        if proof.path.len() != tree_size.ilog2() as usize || proof.index >= self.num_keys {
            return false;
        }
        verify_merkle_proof(proof, vk.hash_koalabear(), self.root).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use slop_algebra::AbstractField;
    use sp1_hypercube::{septic_digest::SepticDigest, UntrustedConfig};
    use sp1_primitives::SP1Field;

    use super::*;

    fn dummy_vk() -> MachineVerifyingKey<SP1GlobalContext> {
        MachineVerifyingKey {
            pc_start: [SP1Field::zero(); 3],
            initial_global_cumulative_sum: SepticDigest::zero(),
            preprocessed_commit: [SP1Field::zero(); 8],
            untrusted_config: UntrustedConfig::zero(),
        }
    }

    fn merkle_proof(index: usize, path_len: usize) -> MerkleProof<SP1GlobalContext> {
        MerkleProof { index, path: vec![[SP1Field::zero(); 8]; path_len] }
    }

    #[test]
    fn rejects_invalid_merkle_proof_shapes() {
        let vk = dummy_vk();
        let verifier = VerifierRecursionVks {
            root: [SP1Field::zero(); 8],
            vk_verification: true,
            num_keys: 6,
        };

        assert!(!verifier.verify(&merkle_proof(0, 2), &vk));
        assert!(!verifier.verify(&merkle_proof(0, 4), &vk));
        assert!(!verifier.verify(&merkle_proof(6, 3), &vk));
        assert!(!verifier.verify(&merkle_proof(7, 3), &vk));
    }

    #[test]
    fn rejects_invalid_merkle_tree_sizes_without_panicking() {
        let vk = dummy_vk();

        for num_keys in [0, usize::MAX] {
            let verifier = VerifierRecursionVks {
                root: [SP1Field::zero(); 8],
                vk_verification: true,
                num_keys,
            };
            assert!(!verifier.verify(&merkle_proof(0, 0), &vk));
        }
    }

    #[test]
    fn still_checks_the_merkle_root_after_shape_validation() {
        let vk = dummy_vk();
        let verifier =
            VerifierRecursionVks { root: vk.hash_koalabear(), vk_verification: true, num_keys: 1 };
        assert!(verifier.verify(&merkle_proof(0, 0), &vk));

        let verifier = VerifierRecursionVks {
            root: [SP1Field::zero(); 8],
            vk_verification: true,
            num_keys: 1,
        };
        assert!(!verifier.verify(&merkle_proof(0, 0), &vk));
    }
}
