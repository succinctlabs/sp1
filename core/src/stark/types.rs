use std::{
    fs::File,
    io::{BufWriter, Seek},
};

use bincode::{deserialize_from, Error};
use p3_commit::{OpenedValues, Pcs};
use p3_matrix::dense::RowMajorMatrix;
use size::Size;

use serde::ser::{Serialize as CustomSerialize, SerializeStruct, Serializer};
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize};
use tracing::trace;

use super::StarkConfig;

pub type Val<SC> = <SC as StarkConfig>::Val;
pub type OpeningProof<SC> = <<SC as StarkConfig>::Pcs as Pcs<Val<SC>, ValMat<SC>>>::Proof;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentCommitment<C> {
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
pub struct SegmentOpenedValues<T> {
    pub main: Vec<AirOpenedValues<T>>,
    pub permutation: Vec<AirOpenedValues<T>>,
    pub quotient: Vec<QuotientOpenedValues<T>>,
}

#[cfg(feature = "perf")]
#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "SC: StarkConfig", deserialize = "SC: StarkConfig"))]
pub struct SegmentProof<SC: StarkConfig> {
    #[serde(bound(serialize = "Com<SC>: Serialize"))]
    #[serde(bound(deserialize = "Com<SC>: Deserialize<'de>"))]
    pub commitment: SegmentCommitment<Com<SC>>,
    #[serde(bound(serialize = "Challenge<SC>: Serialize"))]
    #[serde(bound(deserialize = "Challenge<SC>: Deserialize<'de>"))]
    pub opened_values: SegmentOpenedValues<Challenge<SC>>,
    #[serde(bound(serialize = "SC::Challenge: Serialize"))]
    #[serde(bound(deserialize = "SC::Challenge: Deserialize<'de>"))]
    pub commulative_sums: Vec<SC::Challenge>,
    pub opening_proof: OpeningProof<SC>,
    pub degree_bits: Vec<usize>,
}

// Implement the Serialize trait for SegmentProof
// #[cfg(feature = "perf")]
// impl<SC: StarkConfig> CustomSerialize for SegmentProof<SC> {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         // Define how the struct should be serialized
//         let mut state = serializer.serialize_struct("SegmentProof", 5)?;
//         state.serialize_field("commitment", &self.commitment)?;
//         state.serialize_field("opened_values", &self.opened_values)?;
//         state.serialize_field("commulative_sums", &self.commulative_sums)?;
//         state.serialize_field("opening_proof", &self.opening_proof)?;
//         state.serialize_field("degree_bits", &self.degree_bits)?;
//         state.end()
//     }
// }

// // Implement the Deserialize trait for MyStruct
// #[cfg(feature = "perf")]
// impl<'de, SC: StarkConfig> Deserialize<'de> for SegmentProof<SC> {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         // Define how the struct should be deserialized
//         struct SegmentProofVisitor<SC> {
//             _phantom: std::marker::PhantomData<SC>,
//         }

//         impl<'de, SC: StarkConfig> serde::de::Visitor<'de> for SegmentProofVisitor<SC> {
//             type Value = SegmentProof<SC>;

//             fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
//                 formatter.write_str("struct SegmentProof")
//             }

//             fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
//             where
//                 A: serde::de::MapAccess<'de>,
//             {
//                 let mut commitment = None;
//                 let mut opened_values = None;
//                 let mut commulative_sums = None;
//                 let mut opening_proof = None;
//                 let mut degree_bits = None;

//                 while let Some(key) = map.next_key()? {
//                     match key {
//                         "commitment" => {
//                             if commitment.is_some() {
//                                 return Err(serde::de::Error::duplicate_field("commitment"));
//                             }
//                             commitment = Some(map.next_value()?);
//                         }
//                         "opened_values" => {
//                             if opened_values.is_some() {
//                                 return Err(serde::de::Error::duplicate_field("opened_values"));
//                             }
//                             opened_values = Some(map.next_value()?);
//                         }
//                         "commulative_sums" => {
//                             if commulative_sums.is_some() {
//                                 return Err(serde::de::Error::duplicate_field("commulative_sums"));
//                             }
//                             commulative_sums = Some(map.next_value()?);
//                         }
//                         "opening_proof" => {
//                             if opening_proof.is_some() {
//                                 return Err(serde::de::Error::duplicate_field("opening_proof"));
//                             }
//                             opening_proof = Some(map.next_value()?);
//                         }
//                         "degree_bits" => {
//                             if degree_bits.is_some() {
//                                 return Err(serde::de::Error::duplicate_field("degree_bits"));
//                             }
//                             degree_bits = Some(map.next_value()?);
//                         }
//                         _ => {
//                             let _: serde::de::IgnoredAny = map.next_value()?;
//                         }
//                     }
//                 }

//                 let commitment =
//                     commitment.ok_or_else(|| serde::de::Error::missing_field("commitment"))?;
//                 let opened_values = opened_values
//                     .ok_or_else(|| serde::de::Error::missing_field("opened_values"))?;
//                 let commulative_sums = commulative_sums
//                     .ok_or_else(|| serde::de::Error::missing_field("commulative_sums"))?;
//                 let opening_proof = opening_proof
//                     .ok_or_else(|| serde::de::Error::missing_field("opening_proof"))?;
//                 let degree_bits =
//                     degree_bits.ok_or_else(|| serde::de::Error::missing_field("degree_bits"))?;

//                 Ok(SegmentProof {
//                     commitment,
//                     opened_values,
//                     commulative_sums,
//                     opening_proof,
//                     degree_bits,
//                 })
//             }
//         }

//         // Deserialize the struct using the defined visitor
//         deserializer.deserialize_struct(
//             "SegmentProof",
//             &[
//                 "commitment",
//                 "opened_values",
//                 "commulative_sums",
//                 "opening_proof",
//                 "degree_bits",
//             ],
//             SegmentProofVisitor {
//                 _phantom: std::marker::PhantomData,
//             },
//         )
//     }
// }

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
