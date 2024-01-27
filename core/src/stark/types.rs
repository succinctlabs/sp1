use std::{fs::File, io::BufReader};

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
pub struct MainData<Com, Mat, ProverData>
where
    Mat: Serialize + DeserializeOwned,
    ProverData: Serialize + DeserializeOwned,
{
    pub traces: Vec<Mat>,
    pub main_commit: Com,
    #[serde(bound(serialize = "ProverData: Serialize"))]
    #[serde(bound(deserialize = "ProverData: Deserialize<'de>"))]
    pub main_data: ProverData,
}
// pub struct MainData<SC: StarkConfig> {
//     pub traces: Vec<ValMat<SC>>,
//     pub main_commit: Com<SC>,
//     #[serde(bound(serialize = "PcsProverData<SC>: Serialize"))]
//     #[serde(bound(deserialize = "PcsProverData<SC>: Deserialize<'de>"))]
//     pub main_data: PcsProverData<SC>,
// }

// impl<SC: StarkConfig> MainData<SC> {
impl<Com, Mat, ProverData> MainData<Com, Mat, ProverData> {
    pub fn new(traces: Vec<Mat>, main_commit: Com, main_data: ProverData) -> Self {
        Self {
            traces,
            main_commit,
            main_data,
        }
    }

    pub fn save(&self, file: File) -> Result<MainDataWrapper<Com, Mat, ProverData>, Error>
    where
        MainData<Com, Mat, ProverData>: Serialize,
    {
        bincode::serialize_into(&file, self)?;
        Ok(MainDataWrapper::TempFile(file))
    }

    pub fn to_in_memory(self) -> MainDataWrapper<Com, Mat, ProverData> {
        MainDataWrapper::InMemory(self)
    }
}

pub enum MainDataWrapper<Com, Mat, ProverData> {
    InMemory(MainData<Com, Mat, ProverData>),
    TempFile(File),
    // Remote
}

impl<Com, Mat, ProverData> MainDataWrapper<Com, Mat, ProverData> {
    pub fn materialize(self) -> Result<MainData<Com, Mat, ProverData>, Error>
    where
        MainData<Com, Mat, ProverData>: DeserializeOwned,
    {
        match self {
            Self::InMemory(data) => Ok(data),
            Self::TempFile(file) => {
                let reader = BufReader::new(file);
                let data = deserialize_from(reader)?;
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
