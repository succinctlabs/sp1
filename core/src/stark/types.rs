use std::{
    fs::File,
    io::{BufReader, BufWriter, Seek},
};

use bincode::{deserialize_from, Error};
use p3_air::TwoRowMatrixView;
use p3_commit::{OpenedValues, Pcs};
use p3_field::ExtensionField;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use size::Size;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::trace;

use super::StarkGenericConfig;

pub type Val<SC> = <SC as StarkGenericConfig>::Val;
pub type PackedVal<SC> = <<SC as StarkGenericConfig>::Val as Field>::Packing;
pub type PackedChallenge<SC> = <Challenge<SC> as ExtensionField<Val<SC>>>::ExtensionPacking;
pub type OpeningProof<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<Val<SC>, ValMat<SC>>>::Proof;
pub type OpeningError<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<Val<SC>, ValMat<SC>>>::Error;
pub type Challenge<SC> = <SC as StarkGenericConfig>::Challenge;
#[allow(dead_code)]
type ChallengeMat<SC> = RowMajorMatrix<Challenge<SC>>;
type ValMat<SC> = RowMajorMatrix<Val<SC>>;
pub type Com<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<Val<SC>, ValMat<SC>>>::Commitment;
pub type PcsProverData<SC> =
    <<SC as StarkGenericConfig>::Pcs as Pcs<Val<SC>, ValMat<SC>>>::ProverData;
pub type PcsProof<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<Val<SC>, ValMat<SC>>>::Proof;

pub type QuotientOpenedValues<T> = Vec<T>;

#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "PcsProverData<SC>: Serialize"))]
#[serde(bound(deserialize = "PcsProverData<SC>: Deserialize<'de>"))]
pub struct ShardMainData<SC: StarkGenericConfig> {
    pub traces: Vec<ValMat<SC>>,
    pub main_commit: Com<SC>,
    pub main_data: PcsProverData<SC>,
    pub chip_ids: Vec<String>,
    pub index: usize,
}

impl<SC: StarkGenericConfig> ShardMainData<SC> {
    pub fn new(
        traces: Vec<ValMat<SC>>,
        main_commit: Com<SC>,
        main_data: PcsProverData<SC>,
        chip_ids: Vec<String>,
        index: usize,
    ) -> Self {
        Self {
            traces,
            main_commit,
            main_data,
            chip_ids,
            index,
        }
    }

    pub fn save(&self, file: File) -> Result<ShardMainDataWrapper<SC>, Error>
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

    pub fn to_in_memory(self) -> ShardMainDataWrapper<SC> {
        ShardMainDataWrapper::InMemory(self)
    }
}

pub enum ShardMainDataWrapper<SC: StarkGenericConfig> {
    InMemory(ShardMainData<SC>),
    TempFile(File, u64),
}

impl<SC: StarkGenericConfig> ShardMainDataWrapper<SC> {
    pub fn materialize(self) -> Result<ShardMainData<SC>, Error>
    where
        ShardMainData<SC>: DeserializeOwned,
    {
        match self {
            Self::InMemory(data) => Ok(data),
            Self::TempFile(file, _) => {
                let mut buffer = BufReader::new(&file);
                buffer.seek(std::io::SeekFrom::Start(0))?;
                let data = deserialize_from(&mut buffer)?;
                Ok(data)
            }
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
    pub quotient: Vec<T>,
    pub cumulative_sum: T,
    pub log_degree: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardOpenedValues<T: Serialize> {
    pub chips: Vec<ChipOpenedValues<T>>,
}

#[cfg(feature = "perf")]
#[derive(Serialize, Deserialize)]
pub struct ShardProof<SC: StarkGenericConfig> {
    pub index: usize,
    pub commitment: ShardCommitment<Com<SC>>,
    pub opened_values: ShardOpenedValues<Challenge<SC>>,
    pub opening_proof: OpeningProof<SC>,
    pub chip_ids: Vec<String>,
}

#[cfg(not(feature = "perf"))]
#[derive(Serialize, Deserialize)]
pub struct ShardProof<SC: StarkGenericConfig> {
    pub main_commit: Com<SC>,
    pub traces: Vec<ValMat<SC>>,
    pub permutation_traces: Vec<ChallengeMat<SC>>,
    pub chip_ids: Vec<String>,
}

impl<T: Serialize> ShardOpenedValues<T> {
    pub fn into_values(self) -> OpenedValues<T> {
        let mut main_vals = vec![];
        let mut permutation_vals = vec![];
        let mut quotient_vals = vec![];

        let to_values = |values: AirOpenedValues<T>| vec![values.local, values.next];
        for chip_values in self.chips {
            let ChipOpenedValues {
                main,
                permutation,
                quotient,
                ..
            } = chip_values;

            main_vals.push(to_values(main));
            permutation_vals.push(to_values(permutation));
            quotient_vals.push(vec![quotient]);
        }

        vec![main_vals, permutation_vals, quotient_vals]
    }
}

#[cfg(feature = "perf")]
impl<T> AirOpenedValues<T> {
    pub fn view(&self) -> TwoRowMatrixView<T> {
        TwoRowMatrixView::new(&self.local, &self.next)
    }
}

#[cfg(feature = "perf")]
impl<SC: StarkGenericConfig> ShardProof<SC> {
    pub fn cumulative_sum(&self) -> Challenge<SC> {
        self.opened_values
            .chips
            .iter()
            .map(|c| c.cumulative_sum)
            .sum()
    }
}

#[derive(Serialize, Deserialize)]
pub struct Proof<SC: StarkGenericConfig> {
    pub shard_proofs: Vec<ShardProof<SC>>,
}
