use anyhow::Result;
use backoff::{future::retry, Error as BackoffError, ExponentialBackoff};
use std::time::Duration;
use tonic::Code;

/// Execute an async operation with exponential backoff retries.
///
/// Checks for common network errors and returns a permanent error if the operation fails.
pub async fn with_retry<T, F, Fut>(operation: F, timeout: u64, operation_name: &str) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let timeout = Duration::from_secs(timeout);
    let backoff = ExponentialBackoff {
        initial_interval: Duration::from_secs(1),
        max_interval: Duration::from_secs(120),
        max_elapsed_time: Some(timeout),
        ..Default::default()
    };

    retry(backoff, || async {
        match operation().await {
            Ok(result) => Ok(result),
            Err(e) => {
                // Check for tonic status errors.
                if let Some(status) = e.downcast_ref::<tonic::Status>() {
                    match status.code() {
                        Code::Unavailable => {
                            log::warn!(
                                "Network temporarily unavailable when {} due to {}, retrying...",
                                operation_name,
                                status.message(),
                            );
                            Err(BackoffError::transient(e))
                        }
                        Code::NotFound => {
                            log::error!(
                                "{} not found due to {}",
                                operation_name,
                                status.message(),
                            );
                            Err(BackoffError::permanent(e))
                        }
                        _ => {
                            log::error!(
                                "Permanent error encountered when {}: {} ({})",
                                operation_name,
                                status.message(),
                                status.code()
                            );
                            Err(BackoffError::permanent(e))
                        }
                    }
                } else {
                    // Check for common transport errors.
                    let error_msg = e.to_string().to_lowercase();
                    let is_transient = error_msg.contains("tls handshake") ||
                        error_msg.contains("dns error") ||
                        error_msg.contains("connection reset") ||
                        error_msg.contains("broken pipe") ||
                        error_msg.contains("transport error") ||
                        error_msg.contains("failed to lookup");

                    if is_transient {
                        log::warn!(
                            "Transient transport error when {}: {}, retrying...",
                            operation_name,
                            error_msg
                        );
                        Err(BackoffError::transient(e))
                    } else {
                        log::error!("Permanent error when {}: {}", operation_name, error_msg);
                        Err(BackoffError::permanent(e))
                    }
                }
            }
        }
    })
    .await
}
