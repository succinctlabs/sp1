//! # Network Validation
//!
//! This module provides validation functions for the network sdk.

use super::{FulfillmentStrategy, NetworkMode};

/// Errors that can occur during network validation.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    /// The fulfillment strategy is not compatible with the specified network mode.
    #[error("FulfillmentStrategy::{strategy:?} is not compatible with NetworkMode::{mode:?}")]
    IncompatibleStrategy {
        /// The fulfillment strategy that was attempted.
        strategy: FulfillmentStrategy,
        /// The network mode that was specified.
        mode: NetworkMode,
    },
}

/// Validates that the given fulfillment strategy is compatible with the specified network mode.
///
/// # Arguments
///
/// * `mode` - The network mode (Mainnet or Reserved)
/// * `strategy` - The fulfillment strategy to validate
///
/// # Returns
///
/// Returns `Ok(())` if the strategy is compatible with the mode, otherwise returns
/// a `ValidationError::IncompatibleStrategy`.
///
/// # Examples
///
/// ```
/// use sp1_sdk::network::{
///     validation::validate_strategy_compatibility, FulfillmentStrategy, NetworkMode,
/// };
///
/// // Valid combination
/// assert!(
///     validate_strategy_compatibility(NetworkMode::Mainnet, FulfillmentStrategy::Auction).is_ok()
/// );
///
/// // Invalid combination
/// assert!(
///     validate_strategy_compatibility(NetworkMode::Mainnet, FulfillmentStrategy::Hosted).is_err()
/// );
/// ```
pub fn validate_strategy_compatibility(
    mode: NetworkMode,
    strategy: FulfillmentStrategy,
) -> Result<(), ValidationError> {
    match (mode, strategy) {
        // Valid combinations.
        (NetworkMode::Mainnet, FulfillmentStrategy::Auction) |
        (NetworkMode::Reserved, FulfillmentStrategy::Hosted | FulfillmentStrategy::Reserved) => {
            Ok(())
        }

        // Invalid combinations.
        (mode, strategy) => Err(ValidationError::IncompatibleStrategy { strategy, mode }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_combinations() {
        assert!(validate_strategy_compatibility(
            NetworkMode::Mainnet,
            FulfillmentStrategy::Auction
        )
        .is_ok());
        assert!(validate_strategy_compatibility(
            NetworkMode::Reserved,
            FulfillmentStrategy::Hosted
        )
        .is_ok());
        assert!(validate_strategy_compatibility(
            NetworkMode::Reserved,
            FulfillmentStrategy::Reserved
        )
        .is_ok());
    }

    #[test]
    fn test_invalid_combinations() {
        assert!(validate_strategy_compatibility(
            NetworkMode::Reserved,
            FulfillmentStrategy::Auction
        )
        .is_err());
        assert!(validate_strategy_compatibility(NetworkMode::Mainnet, FulfillmentStrategy::Hosted)
            .is_err());
        assert!(validate_strategy_compatibility(
            NetworkMode::Mainnet,
            FulfillmentStrategy::Reserved
        )
        .is_err());
    }
}
