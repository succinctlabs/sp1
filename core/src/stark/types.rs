use crate::air::MachineAir;
use std::{
    fmt::Debug,
    fs::File,
    io::{BufReader, BufWriter, Seek},
};

use crate::lookup::InteractionBuilder;
use p3_field::PrimeField32;

use p3_air::Air;

use crate::stark::MachineRecord;
use crate::stark::{DefaultProver, MachineProver};
use crate::stark::{ProverConstraintFolder, VerifierConstraintFolder};
use bincode::{deserialize_from, Error};
use hashbrown::HashMap;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::dense::RowMajorMatrixView;
use p3_matrix::stack::VerticalPair;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use size::Size;
use tracing::trace;

use super::{Challenge, Com, OpeningProof, PcsProverData, StarkGenericConfig, Val};

use crate::utils::SP1CoreOpts;

pub type QuotientOpenedValues<T> = Vec<T>;

#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "PcsProverData<SC>: Serialize"))]
#[serde(bound(deserialize = "PcsProverData<SC>: Deserialize<'de>"))]
pub struct ShardMainData<SC: StarkGenericConfig> {
    pub traces: Vec<RowMajorMatrix<Val<SC>>>,
    pub main_commit: Com<SC>,
    pub main_data: PcsProverData<SC>,
    pub chip_ordering: HashMap<String, usize>,
    pub public_values: Vec<SC::Val>,
}

impl<SC: StarkGenericConfig> ShardMainData<SC> {
    pub const fn new(
        traces: Vec<RowMajorMatrix<Val<SC>>>,
        main_commit: Com<SC>,
        main_data: PcsProverData<SC>,
        chip_ordering: HashMap<String, usize>,
        public_values: Vec<Val<SC>>,
    ) -> Self {
        Self {
            traces,
            main_commit,
            main_data,
            chip_ordering,
            public_values,
        }
    }

    pub fn save<A: MachineAir<SC::Val>>(
        &self,
        file: File,
    ) -> Result<ShardMainDataWrapper<SC, A>, Error>
    where
        ShardMainData<SC>: Serialize,
    {
        let mut writer = BufWriter::new(&file);
        bincode::serialize_into(&mut writer, self)?;
        drop(writer);
        let metadata = file.metadata()?;
        let bytes_written = metadata.len();
        trace!(
            "wrote {} while saving ShardMainData",
            Size::from_bytes(bytes_written)
        );
        Ok(ShardMainDataWrapper::TempFile(file, bytes_written))
    }

    pub const fn to_in_memory<A: MachineAir<SC::Val>>(self) -> ShardMainDataWrapper<SC, A> {
        ShardMainDataWrapper::InMemory(self)
    }
}

pub enum ShardMainDataWrapper<SC: StarkGenericConfig, A: MachineAir<SC::Val>> {
    InMemory(ShardMainData<SC>),
    TempFile(File, u64),
    Shard(A::Record),
}

impl<SC: StarkGenericConfig, A: MachineAir<SC::Val>> ShardMainDataWrapper<SC, A>
where
    ShardMainData<SC>: DeserializeOwned,
    SC: 'static + StarkGenericConfig + Send + Sync,
    A: MachineAir<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + Air<InteractionBuilder<Val<SC>>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    A::Record: MachineRecord<Config = SP1CoreOpts>,
    SC::Val: PrimeField32,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    OpeningProof<SC>: Send + Sync,
    ShardMainData<SC>: Serialize + DeserializeOwned,
    SC::Challenger: Clone,
{
    pub fn materialize(self, prover: &DefaultProver<SC, A>) -> Result<ShardMainData<SC>, Error> {
        match self {
            Self::InMemory(data) => Ok(data),
            Self::TempFile(file, _) => {
                let mut buffer = BufReader::new(&file);
                buffer.seek(std::io::SeekFrom::Start(0))?;
                let data = deserialize_from(&mut buffer)?;
                Ok(data)
            }
            Self::Shard(record) => Ok(prover.commit_main(&record)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardCommitment<C> {
    pub main_commit: C,
    pub permutation_commit: C,
    pub quotient_commit: C,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirOpenedValues<T> {
    pub local: Vec<T>,
    pub next: Vec<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChipOpenedValues<T: Serialize> {
    pub preprocessed: AirOpenedValues<T>,
    pub main: AirOpenedValues<T>,
    pub permutation: AirOpenedValues<T>,
    pub quotient: Vec<Vec<T>>,
    pub cumulative_sum: T,
    pub log_degree: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardOpenedValues<T: Serialize> {
    pub chips: Vec<ChipOpenedValues<T>>,
}

/// The maximum number of elements that can be stored in the public values vec.  Both SP1 and recursive
/// proofs need to pad their public_values vec to this length.  This is required since the recursion
/// verification program expects the public values vec to be fixed length.
pub const PROOF_MAX_NUM_PVS: usize = 370;

#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct ShardProof<SC: StarkGenericConfig> {
    pub commitment: ShardCommitment<Com<SC>>,
    pub opened_values: ShardOpenedValues<Challenge<SC>>,
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
    pub fn view(&self) -> VerticalPair<RowMajorMatrixView<'_, T>, RowMajorMatrixView<'_, T>> {
        let a = RowMajorMatrixView::new_row(&self.local);
        let b = RowMajorMatrixView::new_row(&self.next);
        VerticalPair::new(a, b)
    }
}

impl<SC: StarkGenericConfig> ShardProof<SC> {
    pub fn cumulative_sum(&self) -> Challenge<SC> {
        self.opened_values
            .chips
            .iter()
            .map(|c| c.cumulative_sum)
            .sum()
    }

    pub fn log_degree_cpu(&self) -> usize {
        let idx = self.chip_ordering.get("CPU").expect("CPU chip not found");
        self.opened_values.chips[*idx].log_degree
    }

    pub fn contains_cpu(&self) -> bool {
        self.chip_ordering.contains_key("CPU")
    }

    pub fn contains_memory_init(&self) -> bool {
        self.chip_ordering.contains_key("MemoryInit")
    }

    pub fn contains_memory_finalize(&self) -> bool {
        self.chip_ordering.contains_key("MemoryFinalize")
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct MachineProof<SC: StarkGenericConfig> {
    pub shard_proofs: Vec<ShardProof<SC>>,
}

impl<SC: StarkGenericConfig> Debug for MachineProof<SC> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proof")
            .field("shard_proofs", &self.shard_proofs.len())
            .finish()
    }
}

/// PublicValuesDigest is a hash of all the public values that a zkvm program has committed to.
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

/// DeferredDigest is a hash of all the deferred proofs that have been witnessed in the VM.
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
