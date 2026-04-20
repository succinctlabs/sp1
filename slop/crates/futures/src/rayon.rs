use std::{any::Any, backtrace::Backtrace, sync::OnceLock};

use futures::stream::AbortHandle;
use thiserror::Error;

use tokio::sync::oneshot;

use crate::handle::TaskHandle;

static GLOBAL_POOL: OnceLock<()> = OnceLock::new();

/// Initialize the rayon global thread pool.
///
/// Defaults to physical core count when `RAYON_NUM_THREADS` is not set,
/// because SMT siblings cause excessive crossbeam work-stealing contention
/// that outweighs the parallelism benefit.
///
/// Must be called before any rayon work (par_iter, spawn, etc.) to take effect.
/// Safe to call multiple times — only the first call configures the pool.
pub fn init_global_pool() {
    GLOBAL_POOL.get_or_init(|| {
        let mut builder = rayon::ThreadPoolBuilder::new().panic_handler(panic_handler);

        if std::env::var("RAYON_NUM_THREADS").is_err() {
            let physical = num_cpus::get_physical();
            tracing::info!("rayon pool: using {physical} threads (physical cores)");
            builder = builder.num_threads(physical);
        }

        builder.build_global().ok();
    });
}

fn panic_handler(panic_payload: Box<dyn Any + Send>) {
    let backtrace = Backtrace::capture();

    if let Some(message) = panic_payload.downcast_ref::<&str>() {
        eprintln!("Rayon thread panic: '{message}'");
    } else if let Some(message) = panic_payload.downcast_ref::<String>() {
        eprintln!("Rayon thread panic: '{message}'");
    } else {
        eprintln!("Rayon thread panic with unknown payload");
    }

    eprintln!("Backtrace:\n{backtrace:?}");

    // TODO: perhaps safer to abort the process
}

pub enum TaskPool {
    Global,
    Local(rayon::ThreadPool),
}

/// Spawn a task on the global pool.
pub fn spawn<F, R>(func: F) -> TaskHandle<R, TaskJoinError>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    init_global_pool();
    let (tx, rx) = oneshot::channel();
    let (abort_handle, _) = AbortHandle::new_pair();
    rayon::spawn(move || {
        let result = func();
        tx.send(Ok(result)).ok();
    });
    TaskHandle::new(rx, abort_handle)
}

/// Spawn a task that can be aborted using a signle handle.
pub fn spawn_abortable<F, R>(func: F) -> TaskHandle<R, TaskJoinError>
where
    F: FnOnce(AbortHandle) -> R + Send + 'static,
    R: Send + 'static,
{
    init_global_pool();
    let (tx, rx) = oneshot::channel();
    let (abort_handle, abort_registration) = AbortHandle::new_pair();
    rayon::spawn(move || {
        let handle = abort_registration.handle();
        let result = func(handle);
        tx.send(Ok(result)).ok();
    });
    TaskHandle::new(rx, abort_handle)
}

#[derive(Error, Debug)]
#[error("TaskJoinError")]
pub struct TaskJoinError(#[from] oneshot::error::RecvError);

#[derive(Error, Debug)]
#[error("CpuTaskPoolBuilderError: {0}")]
pub struct TaskPoolBuilderError(#[from] rayon::ThreadPoolBuildError);

#[derive(Debug, Default)]
pub struct CpuTaskPoolBuilder(rayon::ThreadPoolBuilder);

impl CpuTaskPoolBuilder {
    pub fn new() -> Self {
        Self(rayon::ThreadPoolBuilder::new())
    }

    pub fn build(self) -> Result<TaskPool, TaskPoolBuilderError> {
        let pool = self.0.build()?;
        Ok(TaskPool::Local(pool))
    }
}

#[cfg(test)]
mod tests {
    use core::panic;
    use tokio::sync::oneshot;

    use super::*;

    #[tokio::test]
    #[should_panic]
    #[allow(unreachable_code)]
    #[allow(unused_variables)]
    async fn test_spawn() {
        let (tx, rx) = oneshot::channel();
        spawn(move || {
            let tx = tx;
            panic!("test");
            tx.send(()).unwrap();
        });
        rx.await.unwrap();
    }
}
