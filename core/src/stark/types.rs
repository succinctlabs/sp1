use std::{
    fs::File,
    io::{BufWriter, Seek},
};

use bincode::{deserialize_from, Error};
use p3_air::TwoRowMatrixView;
use p3_commit::{OpenedValues, Pcs};
use p3_matrix::dense::RowMajorMatrix;
use size::Size;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::trace;

use super::StarkGenericConfig;

pub type Val<SC> = <SC as StarkGenericConfig>::Val;
pub type OpeningProof<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<Val<SC>, ValMat<SC>>>::Proof;
pub type OpeningError<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<Val<SC>, ValMat<SC>>>::Error;
pub type Challenge<SC> = <SC as StarkGenericConfig>::Challenge;
type ValMat<SC> = RowMajorMatrix<Val<SC>>;
pub type Com<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<Val<SC>, ValMat<SC>>>::Commitment;
pub type PcsProverData<SC> =
    <<SC as StarkGenericConfig>::Pcs as Pcs<Val<SC>, ValMat<SC>>>::ProverData;

pub type QuotientOpenedValues<T> = Vec<T>;

#[derive(Serialize, Deserialize)]
#[serde(bound(
    serialize = "SC: StarkGenericConfig",
    deserialize = "SC: StarkGenericConfig"
))]
pub struct MainData<SC: StarkGenericConfig> {
    pub traces: Vec<ValMat<SC>>,
    pub main_commit: Com<SC>,
    #[serde(bound(serialize = "PcsProverData<SC>: Serialize"))]
    #[serde(bound(deserialize = "PcsProverData<SC>: Deserialize<'de>"))]
    pub main_data: PcsProverData<SC>,
    pub chip_ids: Vec<String>,
}

impl<SC: StarkGenericConfig> MainData<SC> {
    pub fn new(
        traces: Vec<ValMat<SC>>,
        main_commit: Com<SC>,
        main_data: PcsProverData<SC>,
        chip_ids: Vec<String>,
    ) -> Self {
        Self {
            traces,
            main_commit,
            main_data,
            chip_ids,
        }
    }

    pub fn save(&self, file: File) -> Result<MainDataWrapper<SC>, Error>
    where
        MainData<SC>: Serialize,
    {
        let start = std::time::Instant::now();
        let mut writer = BufWriter::new(&file);
        bincode::serialize_into(&mut writer, self)?;
        drop(writer);
        let elapsed = start.elapsed();
        let metadata = file.metadata()?;
        let bytes_written = metadata.len();
        trace!(
            "wrote {} after {:?}",
            Size::from_bytes(bytes_written),
            elapsed
        );
        Ok(MainDataWrapper::TempFile(file, bytes_written))
    }

    pub fn to_in_memory(self) -> MainDataWrapper<SC> {
        MainDataWrapper::InMemory(self)
    }
}

pub enum MainDataWrapper<SC: StarkGenericConfig> {
    InMemory(MainData<SC>),
    TempFile(File, u64),
}

impl<SC: StarkGenericConfig> MainDataWrapper<SC> {
    pub fn materialize(self) -> Result<MainData<SC>, Error>
    where
        MainData<SC>: DeserializeOwned,
    {
        match self {
            Self::InMemory(data) => Ok(data),
            Self::TempFile(mut file, _) => {
                file.seek(std::io::SeekFrom::Start(0))?;
                let data = deserialize_from(&mut file)?;

                Ok(data)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ShardCommitment<C> {
    pub main_commit: C,
    pub permutation_commit: C,
    pub quotient_commit: C,
}

#[derive(Debug, Clone, Serialize)]
pub struct AirOpenedValues<T> {
    pub local: Vec<T>,
    pub next: Vec<T>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChipOpenedValues<T: Serialize> {
    pub preprocessed: AirOpenedValues<T>,
    pub main: AirOpenedValues<T>,
    pub permutation: AirOpenedValues<T>,
    pub quotient: Vec<T>,
    pub cumulative_sum: T,
    pub log_degree: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShardOpenedValues<T: Serialize> {
    pub chips: Vec<ChipOpenedValues<T>>,
}

#[cfg(feature = "perf")]
#[derive(Serialize)]
pub struct ShardProof<SC: StarkGenericConfig> {
    pub commitment: ShardCommitment<Com<SC>>,
    pub opened_values: ShardOpenedValues<Challenge<SC>>,
    pub opening_proof: OpeningProof<SC>,
    pub chip_ids: Vec<String>,
}

#[cfg(not(feature = "perf"))]
#[derive(Serialize)]
pub struct ShardProof<SC: StarkGenericConfig> {
    pub main_commit: Com<SC>,
    pub traces: Vec<ValMat<SC>>,
    pub permutation_traces: Vec<ChallengeMat<SC>>,
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

        // vec![
        //     main.into_iter().map(to_values).collect::<Vec<_>>(),
        //     permutation.into_iter().map(to_values).collect::<Vec<_>>(),
        //     quotient.into_iter().map(|v| vec![v]).collect::<Vec<_>>(),
        // ]
    }
}

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

#[derive(Serialize)]
pub struct Proof<SC: StarkGenericConfig> {
    pub shard_proofs: Vec<ShardProof<SC>>,
    pub global_proof: ShardProof<SC>,
}
