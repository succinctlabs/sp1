use anyhow::Result;
use backoff::{future::retry, Error as BackoffError, ExponentialBackoff};
use std::time::Duration;
use tonic::Code;

/// Default timeout for retry operations.
pub const DEFAULT_RETRY_TIMEOUT: Duration = Duration::from_secs(120);

/// Trait for implementing retryable RPC operations.
#[async_trait::async_trait]
pub trait RetryableRpc {
    /// Execute an operation with retries using default timeout.
    async fn with_retry<'a, T, F, Fut>(&'a self, operation: F, operation_name: &str) -> Result<T>
    where
        F: Fn() -> Fut + Send + Sync + 'a,
        Fut: std::future::Future<Output = Result<T>> + Send,
        T: Send;

    /// Execute an operation with retries using custom timeout.
    async fn with_retry_timeout<'a, T, F, Fut>(
        &'a self,
        operation: F,
        timeout: Duration,
        operation_name: &str,
    ) -> Result<T>
    where
        F: Fn() -> Fut + Send + Sync + 'a,
        Fut: std::future::Future<Output = Result<T>> + Send,
        T: Send;
}

/// Execute an async operation with exponential backoff retries.
pub async fn retry_operation<T, F, Fut>(
    operation: F,
    timeout: Option<Duration>,
    operation_name: &str,
) -> Result<T>
where
    F: Fn() -> Fut + Send + Sync,
    Fut: std::future::Future<Output = Result<T>> + Send,
{
    let backoff = ExponentialBackoff {
        initial_interval: Duration::from_secs(1),
        max_interval: Duration::from_secs(120),
        max_elapsed_time: timeout,
        ..Default::default()
    };

    retry(backoff, || async {
        match operation().await {
            Ok(result) => Ok(result),
            Err(e) => {
                // Check for tonic status errors.
                if let Some(status) = e.downcast_ref::<tonic::Status>() {
                    match status.code() {
                        Code::Unavailable
                        | Code::DeadlineExceeded
                        | Code::Internal
                        | Code::Aborted
                        | Code::Cancelled => {
                            tracing::warn!(
                                "Network temporarily unavailable when {} due to {}, retrying...",
                                operation_name,
                                status.message(),
                            );
                            Err(BackoffError::transient(e))
                        }
                        Code::NotFound => {
                            tracing::error!(
                                "{} not found due to {}",
                                operation_name,
                                status.message(),
                            );
                            Err(BackoffError::permanent(e))
                        }
                        // Dropped connection on the reused channel; failed before send, safe to
                        // retry — see `is_connection_not_ready`.
                        _ if is_connection_not_ready(status) => {
                            tracing::warn!(
                                "Connection not ready when {} ({}), retrying...",
                                operation_name,
                                status.message(),
                            );
                            Err(BackoffError::transient(e))
                        }
                        _ => {
                            tracing::error!(
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
                    let error_debug_msg = format!("{e:?}");

                    if error_debug_msg.contains("no native certs found") {
                        tracing::error!(
                            "Permanent error when {}: no native certs found",
                            operation_name
                        );
                        Err(BackoffError::permanent(e))
                    } else {
                        let is_transient = error_msg.contains("tls handshake")
                            || error_msg.contains("dns error")
                            || error_msg.contains("connection reset")
                            || error_msg.contains("broken pipe")
                            || error_msg.contains("transport error")
                            || error_msg.contains("failed to lookup")
                            || error_msg.contains("timeout")
                            || error_msg.contains("deadline exceeded")
                            || error_msg.contains("error sending request for url");

                        if is_transient {
                            tracing::warn!(
                                "Transient transport error when {}: {}, retrying...",
                                operation_name,
                                error_msg
                            );
                            Err(BackoffError::transient(e))
                        } else {
                            tracing::error!(
                                "Permanent error when {}: {}",
                                operation_name,
                                error_msg
                            );
                            Err(BackoffError::permanent(e))
                        }
                    }
                }
            }
        }
    })
    .await
}

/// True for tonic's `poll_ready` failure on a reused channel — reported by the generated client as
/// `Status::unknown("Service was not ready: ...")` when the channel's connection has dropped (e.g.
/// an idle connection reaped by a load balancer).
///
/// The gate fails before the request is sent, so it's safe to retry; the channel re-establishes on
/// the next attempt. Matched narrowly on `Code::Unknown` plus this prefix so other errors stay
/// permanent.
fn is_connection_not_ready(status: &tonic::Status) -> bool {
    status.code() == Code::Unknown
        && status.message().to_lowercase().contains("service was not ready")
}

#[cfg(test)]
mod tests {
    use super::{is_connection_not_ready, retry_operation, Result};
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    use tonic::Status;

    #[test]
    fn not_ready_is_the_only_retryable_unknown() {
        // The poll_ready signature, matched case-insensitively.
        assert!(is_connection_not_ready(&Status::unknown(
            "Service was not ready: transport error"
        )));
        assert!(is_connection_not_ready(&Status::unknown("SERVICE WAS NOT READY: x")));

        // Regression guard: any other error must stay permanent — other `Unknown` messages, and
        // the same message under any other code. We never retry on free-form server text.
        assert!(!is_connection_not_ready(&Status::unknown("invalid request timeout value")));
        assert!(!is_connection_not_ready(&Status::invalid_argument("Service was not ready: x")));
        assert!(!is_connection_not_ready(&Status::resource_exhausted("Service was not ready: x")));
    }

    #[tokio::test]
    async fn retry_loop_recovers_from_not_ready() {
        let attempts = AtomicUsize::new(0);
        let res = retry_operation(
            || async {
                if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(Status::unknown("Service was not ready: transport error").into())
                } else {
                    Ok(())
                }
            },
            Some(Duration::from_secs(10)),
            "test op",
        )
        .await;
        assert!(res.is_ok());
        assert_eq!(attempts.load(Ordering::SeqCst), 2, "should retry once, then succeed");
    }

    #[tokio::test]
    async fn retry_loop_fails_fast_on_permanent() {
        let attempts = AtomicUsize::new(0);
        let res: Result<()> = retry_operation(
            || async {
                attempts.fetch_add(1, Ordering::SeqCst);
                Err(Status::unknown("invalid argument").into())
            },
            Some(Duration::from_secs(10)),
            "test op",
        )
        .await;
        assert!(res.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 1, "permanent errors must not retry");
    }
}
