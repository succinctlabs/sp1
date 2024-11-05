use rayon::prelude::*;

pub struct ParallelExecutor {
    threads: usize,
}

impl ParallelExecutor {
    pub fn new(threads: usize) -> Self {
        Self { threads }
    }

    pub fn execute<F, T>(&self, workload: Vec<F>) -> Vec<T>
    where
        F: Fn() -> T + Send + Sync,
        T: Send,
    {
        workload.par_iter()
               .map(|f| f())
               .collect()
    }
}
