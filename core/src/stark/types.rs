use std::{
    fs::File,
    io::{BufWriter, Seek},
};

use bincode::{deserialize_from, Error};
use p3_commit::{OpenedValues, Pcs};
use p3_matrix::dense::RowMajorMatrix;
use size::Size;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::trace;

use super::StarkConfig;

type Val<SC> = <SC as StarkConfig>::Val;
type OpeningProof<SC> = <<SC as StarkConfig>::Pcs as Pcs<Val<SC>, ValMat<SC>>>::Proof;
pub type OpeningError<SC> = <<SC as StarkConfig>::Pcs as Pcs<Val<SC>, ValMat<SC>>>::Error;
pub type Challenge<SC> = <SC as StarkConfig>::Challenge;
type ValMat<SC> = RowMajorMatrix<Val<SC>>;
#[allow(dead_code)]
type ChallengeMat<SC> = RowMajorMatrix<Challenge<SC>>;
type Com<SC> = <<SC as StarkConfig>::Pcs as Pcs<Val<SC>, ValMat<SC>>>::Commitment;
type PcsProverData<SC> = <<SC as StarkConfig>::Pcs as Pcs<Val<SC>, ValMat<SC>>>::ProverData;

pub type QuotientOpenedValues<T> = Vec<T>;

#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "SC: StarkConfig", deserialize = "SC: StarkConfig"))]
pub struct MainData<SC: StarkConfig> {
    pub traces: Vec<ValMat<SC>>,
    pub main_commit: Com<SC>,
    #[serde(bound(serialize = "PcsProverData<SC>: Serialize"))]
    #[serde(bound(deserialize = "PcsProverData<SC>: Deserialize<'de>"))]
    pub main_data: PcsProverData<SC>,
}

impl<SC: StarkConfig> MainData<SC> {
    pub fn new(
        traces: Vec<ValMat<SC>>,
        main_commit: Com<SC>,
        main_data: PcsProverData<SC>,
    ) -> Self {
        Self {
            traces,
            main_commit,
            main_data,
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

pub enum MainDataWrapper<SC: StarkConfig> {
    InMemory(MainData<SC>),
    TempFile(File, u64),
}

impl<SC: StarkConfig> MainDataWrapper<SC> {
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

#[derive(Debug, Clone)]
pub struct SegmentCommitment<C> {
    pub main_commit: C,
    pub permutation_commit: C,
    pub quotient_commit: C,
}

#[derive(Debug, Clone)]
pub struct AirOpenedValues<T> {
    pub local: Vec<T>,
    pub next: Vec<T>,
}

#[derive(Debug, Clone)]
pub struct SegmentOpenedValues<T> {
    pub main: Vec<AirOpenedValues<T>>,
    pub permutation: Vec<AirOpenedValues<T>>,
    pub quotient: Vec<QuotientOpenedValues<T>>,
}

#[cfg(feature = "perf")]
pub struct SegmentProof<SC: StarkConfig> {
    pub commitment: SegmentCommitment<Com<SC>>,
    pub opened_values: SegmentOpenedValues<Challenge<SC>>,
    pub commulative_sums: Vec<SC::Challenge>,
    pub opening_proof: OpeningProof<SC>,
    pub degree_bits: Vec<usize>,
}

#[cfg(not(feature = "perf"))]
pub struct SegmentProof<SC: StarkConfig> {
    pub main_commit: Com<SC>,
    pub traces: Vec<ValMat<SC>>,
    pub permutation_traces: Vec<ChallengeMat<SC>>,
}

impl<T> SegmentOpenedValues<T> {
    pub fn into_values(self) -> OpenedValues<T> {
        let Self {
            main,
            permutation,
            quotient,
        } = self;

        let to_values = |values: AirOpenedValues<T>| vec![values.local, values.next];

        vec![
            main.into_iter().map(to_values).collect::<Vec<_>>(),
            permutation.into_iter().map(to_values).collect::<Vec<_>>(),
            quotient.into_iter().map(|v| vec![v]).collect::<Vec<_>>(),
        ]
    }
}
