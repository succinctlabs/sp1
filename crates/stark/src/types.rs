#![allow(missing_docs)]

use std::fmt::Debug;

use hashbrown::HashMap;
use itertools::Itertools;
use p3_matrix::{dense::RowMajorMatrixView, stack::VerticalPair};
use serde::{Deserialize, Serialize};

use super::{Challenge, Com, OpeningProof, StarkGenericConfig, Val};
use crate::{septic_digest::SepticDigest, shape::OrderedShape};

pub type QuotientOpenedValues<T> = Vec<T>;

pub struct ShardMainData<SC: StarkGenericConfig, M, P> {
    pub traces: Vec<M>,
    pub main_commit: Com<SC>,
    pub main_data: P,
    pub chip_ordering: HashMap<String, usize>,
    pub public_values: Vec<SC::Val>,
}

impl<SC: StarkGenericConfig, M, P> ShardMainData<SC, M, P> {
    pub const fn new(
        traces: Vec<M>,
        main_commit: Com<SC>,
        main_data: P,
        chip_ordering: HashMap<String, usize>,
        public_values: Vec<Val<SC>>,
    ) -> Self {
        Self { traces, main_commit, main_data, chip_ordering, public_values }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardCommitment<C> {
    pub main_commit: C,
    pub permutation_commit: C,
    pub quotient_commit: C,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "T: Serialize"))]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
pub struct AirOpenedValues<T> {
    pub local: Vec<T>,
    pub next: Vec<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "F: Serialize, EF: Serialize"))]
#[serde(bound(deserialize = "F: Deserialize<'de>, EF: Deserialize<'de>"))]
pub struct ChipOpenedValues<F, EF> {
    pub preprocessed: AirOpenedValues<EF>,
    pub main: AirOpenedValues<EF>,
    pub permutation: AirOpenedValues<EF>,
    pub quotient: Vec<Vec<EF>>,
    pub global_cumulative_sum: SepticDigest<F>,
    pub local_cumulative_sum: EF,
    pub log_degree: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardOpenedValues<F, EF> {
    pub chips: Vec<ChipOpenedValues<F, EF>>,
}

/// The maximum number of elements that can be stored in the public values vec.  Both SP1 and
/// recursive proofs need to pad their public values vec to this length.  This is required since the
/// recursion verification program expects the public values vec to be fixed length.
pub const PROOF_MAX_NUM_PVS: usize = 231;

#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct ShardProof<SC: StarkGenericConfig> {
    pub commitment: ShardCommitment<Com<SC>>,
    pub opened_values: ShardOpenedValues<Val<SC>, Challenge<SC>>,
    pub opening_proof: OpeningProof<SC>,
    pub chip_ordering: HashMap<String, usize>,
    pub public_values: Vec<Val<SC>>,
}

impl<SC: StarkGenericConfig> Debug for ShardProof<SC> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShardProof").finish()
    }
}

impl<T: Send + Sync + Clone> AirOpenedValues<T> {
    #[must_use]
    pub fn view(&self) -> VerticalPair<RowMajorMatrixView<'_, T>, RowMajorMatrixView<'_, T>> {
        let a = RowMajorMatrixView::new_row(&self.local);
        let b = RowMajorMatrixView::new_row(&self.next);
        VerticalPair::new(a, b)
    }
}

impl<SC: StarkGenericConfig> ShardProof<SC> {
    pub fn local_cumulative_sum(&self) -> Challenge<SC> {
        self.opened_values.chips.iter().map(|c| c.local_cumulative_sum).sum()
    }

    pub fn global_cumulative_sum(&self) -> SepticDigest<Val<SC>> {
        self.opened_values.chips.iter().map(|c| c.global_cumulative_sum).sum()
    }

    pub fn log_degree_cpu(&self) -> usize {
        let idx = self.chip_ordering.get("Cpu").expect("Cpu chip not found");
        self.opened_values.chips[*idx].log_degree
    }

    pub fn contains_cpu(&self) -> bool {
        self.chip_ordering.contains_key("Cpu")
    }

    pub fn contains_global_memory_init(&self) -> bool {
        self.chip_ordering.contains_key("MemoryGlobalInit")
    }

    pub fn contains_global_memory_finalize(&self) -> bool {
        self.chip_ordering.contains_key("MemoryGlobalFinalize")
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct MachineProof<SC: StarkGenericConfig> {
    pub shard_proofs: Vec<ShardProof<SC>>,
}

impl<SC: StarkGenericConfig> Debug for MachineProof<SC> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proof").field("shard_proofs", &self.shard_proofs.len()).finish()
    }
}

/// The hash of all the public values that a zkvm program has committed to.
pub struct PublicValuesDigest(pub [u8; 32]);

impl From<[u32; 8]> for PublicValuesDigest {
    fn from(arr: [u32; 8]) -> Self {
        let mut bytes = [0u8; 32];
        for (i, word) in arr.iter().enumerate() {
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
        PublicValuesDigest(bytes)
    }
}

/// The hash of all the deferred proofs that have been witnessed in the VM.
pub struct DeferredDigest(pub [u8; 32]);

impl From<[u32; 8]> for DeferredDigest {
    fn from(arr: [u32; 8]) -> Self {
        let mut bytes = [0u8; 32];
        for (i, word) in arr.iter().enumerate() {
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
        DeferredDigest(bytes)
    }
}

impl<SC: StarkGenericConfig> ShardProof<SC> {
    pub fn shape(&self) -> OrderedShape {
        OrderedShape {
            inner: self
                .chip_ordering
                .iter()
                .sorted_by_key(|(_, idx)| *idx)
                .zip(self.opened_values.chips.iter())
                .map(|((name, _), values)| (name.to_owned(), values.log_degree))
                .collect(),
        }
    }
}
