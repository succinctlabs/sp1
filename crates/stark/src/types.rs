#![allow(missing_docs)]

use core::fmt;
use std::{cmp::Reverse, collections::BTreeSet, fmt::Debug};

use hashbrown::HashMap;
use itertools::Itertools;
use p3_matrix::{
    dense::{RowMajorMatrix, RowMajorMatrixView},
    stack::VerticalPair,
    Matrix,
};
use serde::{Deserialize, Serialize};

use super::{Challenge, Com, OpeningProof, StarkGenericConfig, Val};
use crate::air::InteractionScope;

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
    pub global_main_commit: C,
    pub local_main_commit: C,
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
#[serde(bound(serialize = "T: Serialize"))]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
pub struct ChipOpenedValues<T> {
    pub preprocessed: AirOpenedValues<T>,
    pub main: AirOpenedValues<T>,
    pub permutation: AirOpenedValues<T>,
    pub quotient: Vec<Vec<T>>,
    pub global_cumulative_sum: T,
    pub local_cumulative_sum: T,
    pub log_degree: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardOpenedValues<T> {
    pub chips: Vec<ChipOpenedValues<T>>,
}

/// The maximum number of elements that can be stored in the public values vec.  Both SP1 and
/// recursive proofs need to pad their public values vec to this length.  This is required since the
/// recursion verification program expects the public values vec to be fixed length.
pub const PROOF_MAX_NUM_PVS: usize = 371;

#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct ShardProof<SC: StarkGenericConfig> {
    pub commitment: ShardCommitment<Com<SC>>,
    pub opened_values: ShardOpenedValues<Challenge<SC>>,
    pub opening_proof: OpeningProof<SC>,
    pub chip_ordering: HashMap<String, usize>,
    pub public_values: Vec<Val<SC>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct ProofShape {
    pub chip_information: Vec<(String, usize)>,
}

impl ProofShape {
    #[must_use]
    pub fn from_traces<V: Clone + Send + Sync>(
        global_traces: Option<&[(String, RowMajorMatrix<V>)]>,
        local_traces: &[(String, RowMajorMatrix<V>)],
    ) -> Self {
        global_traces
            .into_iter()
            .flatten()
            .chain(local_traces.iter())
            .map(|(name, trace)| (name.clone(), trace.height().ilog2() as usize))
            .sorted_by_key(|(_, height)| *height)
            .collect()
    }
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
    pub fn cumulative_sum(&self, scope: InteractionScope) -> Challenge<SC> {
        self.opened_values
            .chips
            .iter()
            .map(|c| match scope {
                InteractionScope::Global => c.global_cumulative_sum,
                InteractionScope::Local => c.local_cumulative_sum,
            })
            .sum()
    }

    pub fn log_degree_cpu(&self) -> usize {
        let idx = self.chip_ordering.get("CPU").expect("CPU chip not found");
        self.opened_values.chips[*idx].log_degree
    }

    pub fn contains_cpu(&self) -> bool {
        self.chip_ordering.contains_key("CPU")
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
    pub fn shape(&self) -> ProofShape {
        ProofShape {
            chip_information: self
                .chip_ordering
                .iter()
                .sorted_by_key(|(_, idx)| *idx)
                .zip(self.opened_values.chips.iter())
                .map(|((name, _), values)| (name.to_owned(), values.log_degree))
                .collect(),
        }
    }
}

impl FromIterator<(String, usize)> for ProofShape {
    fn from_iter<T: IntoIterator<Item = (String, usize)>>(iter: T) -> Self {
        let set = iter
            .into_iter()
            .map(|(name, log_degree)| (Reverse(log_degree), name))
            .collect::<BTreeSet<_>>();
        Self {
            chip_information: set
                .into_iter()
                .map(|(Reverse(log_degree), name)| (name, log_degree))
                .collect(),
        }
    }
}

impl IntoIterator for ProofShape {
    type Item = (String, usize);

    type IntoIter = <Vec<(String, usize)> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.chip_information.into_iter()
    }
}

impl fmt::Display for ProofShape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Print the proof shapes in a human-readable format
        writeln!(f, "Proofshape:")?;
        for (name, log_degree) in &self.chip_information {
            writeln!(f, "{name}: {}", 1 << log_degree)?;
        }
        Ok(())
    }
}
