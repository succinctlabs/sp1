//! # Network Utils
//!
//! This module provides utility functions for the network module.

use alloy_signer::{Signature, SignerSync};
use prost::Message;
use serde::Serialize;
use thiserror::Error;

pub(crate) trait Signable: Message {
    fn sign<S: SignerSync>(&self, signer: &S) -> Signature;
}

impl<T: Message> Signable for T {
    fn sign<S: SignerSync>(&self, signer: &S) -> Signature {
        signer.sign_message_sync(&self.encode_to_vec()).unwrap()
    }
}

#[derive(Error, Debug)]
pub(crate) enum JsonFormatError {
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

pub(crate) fn format_json_message<T>(body: &T) -> Result<Vec<u8>, JsonFormatError>
where
    T: Message + Serialize,
{
    match serde_json::to_string(body) {
        Ok(json_str) => {
            if json_str.starts_with('"') && json_str.ends_with('"') {
                let inner = &json_str[1..json_str.len() - 1];
                let unescaped = inner.replace("\\\"", "\"");
                Ok(unescaped.into_bytes())
            } else {
                Ok(json_str.into_bytes())
            }
        }
        Err(e) => Err(JsonFormatError::SerializationError(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as ProstMessage;
    use serde::{Deserialize, Serialize};

    // Test message for JSON formatting.
    #[derive(Clone, ProstMessage, Serialize, Deserialize)]
    struct TestMessage {
        #[prost(string, tag = 1)]
        value: String,
    }

    #[test]
    fn test_format_json_message_simple() {
        let msg = TestMessage { value: "hello".to_string() };
        let result = format_json_message(&msg).unwrap();
        assert_eq!(result, b"{\"value\":\"hello\"}");
    }

    #[test]
    fn test_format_json_message_with_quotes() {
        let msg = TestMessage { value: "hello \"world\"".to_string() };
        let result = format_json_message(&msg).unwrap();
        assert_eq!(result, b"{\"value\":\"hello \\\"world\\\"\"}");
    }
}
