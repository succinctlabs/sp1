use anyhow::{anyhow, Result};

mod artifacts;
pub use artifacts::*;

mod machine;
pub use machine::*;

pub mod cluster {
    tonic::include_proto!("cluster");
}
pub use cluster::*;

pub mod worker {
    tonic::include_proto!("worker");
}
pub use worker::*;

mod utils;
pub use utils::*;

#[rustfmt::skip]
pub mod network_base_types;

impl WorkerType {
    pub fn from_task_type(task_type: TaskType) -> Self {
        match task_type {
            TaskType::Controller
            | TaskType::PlonkWrap
            | TaskType::Groth16Wrap
            | TaskType::UtilVkeyMapController
            | TaskType::ExecuteOnly
            | TaskType::CoreExecute => WorkerType::Cpu,
            TaskType::ProveShard
            | TaskType::RecursionReduce
            | TaskType::RecursionDeferred
            | TaskType::ShrinkWrap
            | TaskType::SetupVkey
            | TaskType::UtilVkeyMapChunk => WorkerType::Gpu,
            TaskType::MarkerDeferredRecord | TaskType::UnspecifiedTaskType => WorkerType::None,
        }
    }
}

impl WorkerTask {
    pub fn data(&self) -> Result<&TaskData> {
        self.data.as_ref().ok_or(anyhow!("no task data"))
    }
}
