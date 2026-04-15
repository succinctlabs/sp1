use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use crate::worker::TaskMetadata;

#[derive(Debug, Clone, Default)]
pub struct ProverMetrics {
    permit_ms: Arc<AtomicU64>,
}

impl ProverMetrics {
    pub fn new() -> Self {
        Self { permit_ms: Arc::new(AtomicU64::new(0)) }
    }

    pub fn gpu_ms(&self) -> u64 {
        self.permit_ms.load(Ordering::Relaxed)
    }

    pub fn increment_permit_time(&self, time: Duration) {
        let ms = time.as_millis() as u64;
        self.permit_ms.fetch_add(ms, Ordering::Relaxed);
    }

    pub fn to_metadata(&self) -> TaskMetadata {
        let gpu_ms = self.permit_ms.load(Ordering::Relaxed);
        TaskMetadata { gpu_ms: Some(gpu_ms) }
    }
}
