#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_performance_metrics() {
        let mut metrics = PerformanceMetrics::new();
        thread::sleep(Duration::from_millis(100));
        metrics.record_operation("test_op", Duration::from_millis(100));
        
        assert_eq!(metrics.operations.len(), 1);
    }
}
