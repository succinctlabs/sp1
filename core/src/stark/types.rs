use std::{
    fs::File,
    io::{BufReader, Read},
    marker::PhantomData,
    path::Path,
    sync::Arc,
};

use bincode::{deserialize_from, Error};
use p3_commit::{OpenedValues, Pcs};
use p3_matrix::dense::RowMajorMatrix;

use p3_uni_stark::StarkConfig;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

type Val<SC> = <SC as StarkConfig>::Val;
type OpenningProof<SC> = <<SC as StarkConfig>::Pcs as Pcs<Val<SC>, ValMat<SC>>>::Proof;
pub type OpenningError<SC> = <<SC as StarkConfig>::Pcs as Pcs<Val<SC>, ValMat<SC>>>::Error;
pub type Challenge<SC> = <SC as StarkConfig>::Challenge;
type ValMat<SC> = RowMajorMatrix<Val<SC>>;
type ChallengeMat<SC> = RowMajorMatrix<Challenge<SC>>;
type Com<SC> = <<SC as StarkConfig>::Pcs as Pcs<Val<SC>, ValMat<SC>>>::Commitment;
type PcsProverData<SC> = <<SC as StarkConfig>::Pcs as Pcs<Val<SC>, ValMat<SC>>>::ProverData;

pub type QuotientOpenedValues<T> = Vec<T>;

pub struct SegmentDebugProof<SC: StarkConfig> {
    pub main_commit: Com<SC>,
    pub traces: Vec<ValMat<SC>>,
    pub permutation_traces: Vec<ChallengeMat<SC>>,
}

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

    pub fn save(&self, path: &Path) -> Result<MainDataWrapper<SC>, Error>
    where
        MainData<SC>: Serialize,
    {
        println!("writing to file: {:?}", path);
        let file = File::create(path)?;
        bincode::serialize_into(&file, self)?;
        println!("done writing to file: {:?}", path);
        // Print size of file in mb
        let metadata = std::fs::metadata(path)?;
        println!(
            "Main data size: {} mb",
            metadata.len() as f64 / 1024.0 / 1024.0
        );
        Ok(MainDataWrapper::TempFile(
            path.to_str().unwrap().to_string(),
        ))
    }

    pub fn to_in_memory(self) -> MainDataWrapper<SC> {
        MainDataWrapper::InMemory(self)
    }
}

pub enum MainDataWrapper<SC: StarkConfig> {
    InMemory(MainData<SC>),
    TempFile(String),
    // Remote
}

impl<SC: StarkConfig> MainDataWrapper<SC> {
    pub fn materialize(self) -> Result<MainData<SC>, Error>
    where
        MainData<SC>: DeserializeOwned,
    {
        match self {
            Self::InMemory(data) => Ok(data),
            Self::TempFile(path) => {
                let file = File::open(path)?;
                let reader = BufReader::new(file);
                let data = deserialize_from(reader)?;
                Ok(data)
                // Ok(data)
            }
        }
    }
}

// impl<SC: StarkConfig> Clone for MainDataWrapper<SC> {
//     fn clone(&self) -> Self {
//         match self {
//             Self::InMemory(data) => Self::InMemory(data.clone()),
//             Self::TempFile(file) => Self::TempFile(file.clone()),
//         }
//     }
// }

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

pub struct SegmentProof<SC: StarkConfig> {
    pub commitment: SegmentCommitment<Com<SC>>,
    pub opened_values: SegmentOpenedValues<Challenge<SC>>,
    pub commulative_sums: Vec<SC::Challenge>,
    pub openning_proof: OpenningProof<SC>,
    pub degree_bits: Vec<usize>,
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
