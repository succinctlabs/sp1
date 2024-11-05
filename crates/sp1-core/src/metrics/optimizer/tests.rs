#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parallel_executor() {
        let executor = ParallelExecutor::new(4);
        let workload: Vec<Box<dyn Fn() -> i32>> = vec![
            Box::new(|| 1),
            Box::new(|| 2),
            Box::new(|| 3),
        ];
        
        let results = executor.execute(workload);
        assert_eq!(results, vec![1, 2, 3]);
    }
}
