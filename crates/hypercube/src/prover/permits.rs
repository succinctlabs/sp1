use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use thiserror::Error;
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore};
use tracing::Span;

/// A permit for the prover.
#[derive(Debug)]
pub struct ProverPermit {
    /// The underlying permit.
    #[allow(dead_code)]
    permit: OwnedSemaphorePermit,
    /// The span for the permit lifetime.
    span: Span,
    /// The time the permit was acquired.
    time: tokio::time::Instant,
}

impl ProverPermit {
    /// Release the permit and return the duration it was held for.
    #[must_use]
    pub fn release(self) -> Duration {
        self.time.elapsed()
    }
}

impl Drop for ProverPermit {
    fn drop(&mut self) {
        let duration = self.time.elapsed();
        tracing::debug!(parent: &self.span, "permit acquired for {:?} ", duration);
    }
}

/// A semaphore for the prover.
#[derive(Debug, Clone)]
pub struct ProverSemaphore {
    /// The underlying semaphore.
    sem: Arc<Semaphore>,
    ordinary_weight: u32,
    cells_per_permit: Option<fn() -> usize>,
    idle_budget: Arc<AtomicUsize>,
}

impl ProverSemaphore {
    /// Create a new prover semaphore with the given number of permits.
    #[must_use]
    #[inline]
    pub fn new(max_permits: usize) -> Self {
        Self {
            sem: Arc::new(Semaphore::new(max_permits)),
            ordinary_weight: 1,
            cells_per_permit: None,
            idle_budget: Arc::default(),
        }
    }

    /// Share a device between traces in proportion to their estimated workspace.
    /// Operations using a cached mutable key acquire the entire budget.
    #[must_use]
    pub fn with_trace_budget(permits: u32, cells_per_permit: fn() -> usize) -> Self {
        assert!(permits > 0);
        Self {
            sem: Arc::new(Semaphore::new(permits as usize)),
            ordinary_weight: permits,
            cells_per_permit: Some(cells_per_permit),
            idle_budget: Arc::default(),
        }
    }

    /// Whether independent trace workspaces may run on different streams.
    pub fn allows_concurrent_traces(&self) -> bool {
        self.cells_per_permit.is_some()
    }

    /// Acquire resources for a shard with its own trace workspace. With a regular
    /// semaphore there is no need to compute the shard's size. The concurrency
    /// limit can reserve additional permits for large host-side staging buffers.
    pub async fn acquire_for_trace(
        self,
        max_concurrent: u32,
        estimate: impl FnOnce() -> usize,
    ) -> Result<ProverPermit, ProverAcquireError> {
        let weight = if let Some(cells_per_permit) = self.cells_per_permit {
            let cells = estimate();
            // Outstanding permits already account for active workspaces. Sampling
            // free device bytes again mid-wave would charge for those allocations twice.
            let mut budget = self.idle_budget.load(Ordering::Relaxed);
            if budget == 0 || self.sem.available_permits() == self.ordinary_weight as usize {
                budget = cells_per_permit().max(1);
                self.idle_budget.store(budget, Ordering::Relaxed);
            }
            let minimum = self.ordinary_weight.div_ceil(max_concurrent.max(1));
            let permits =
                cells.div_ceil(budget).clamp(minimum as usize, self.ordinary_weight as usize)
                    as u32;
            tracing::debug!(cells, budget, permits, "admitting independent trace");
            permits
        } else {
            self.ordinary_weight
        };
        self.acquire_many(weight).await
    }

    /// Acquire a permit.
    #[inline]
    pub async fn acquire(self) -> Result<ProverPermit, ProverAcquireError> {
        let weight = self.ordinary_weight;
        self.acquire_many(weight).await
    }

    /// Acquire multiple permits.
    #[inline]
    pub async fn acquire_many(self, n: u32) -> Result<ProverPermit, ProverAcquireError> {
        let span = tracing::Span::current();
        let permit = self.sem.acquire_many_owned(n).await?;
        let time = tokio::time::Instant::now();
        Ok(ProverPermit { permit, span, time })
    }
}

/// An error that occurs when acquiring a permit.
#[derive(Debug, Error)]
#[error("failed to acquire permit")]
pub struct ProverAcquireError(#[from] AcquireError);
