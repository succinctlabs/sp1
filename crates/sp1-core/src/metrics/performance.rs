use std::time::{Duration, Instant};

pub struct PerformanceMetrics {
    start_time: Instant,
    operations: Vec<(String, Duration)>,
}

impl PerformanceMetrics {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            operations: Vec::new(),
        }
    }

    pub fn record_operation(&mut self, name: &str, duration: Duration) {
        self.operations.push((name.to_string(), duration));
    }
}
