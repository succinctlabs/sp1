use alloc::vec::Vec;

use super::kzg::{BatchOpeningProof, Digest, OpeningProof};

#[derive(Debug)]
pub(crate) struct PlonkProof {
    pub(crate) lro: [Digest; 3],
    pub(crate) z: Digest,
    pub(crate) h: [Digest; 3],
    pub(crate) bsb22_commitments: Vec<Digest>,
    pub(crate) batched_proof: BatchOpeningProof,
    pub(crate) z_shifted_opening: OpeningProof,
}
