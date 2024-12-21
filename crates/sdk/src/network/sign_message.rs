#![allow(deprecated)]

use alloy_primitives::{Address, Signature};
use prost::Message;
use thiserror::Error;

use crate::network::proto::network::{FulfillProofRequest, MessageFormat, RequestProofRequest};
use crate::network::utils::{format_json_message, JsonFormatError};

#[allow(dead_code)]
pub trait SignedMessage {
    fn signature(&self) -> Vec<u8>;
    fn nonce(&self) -> Result<u64, MessageError>;
    fn message(&self) -> Result<Vec<u8>, MessageError>;
    fn recover_sender(&self) -> Result<(Address, Vec<u8>), RecoverSenderError>;
}

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum MessageError {
    #[error("Empty message")]
    EmptyMessage,
    #[error("JSON error: {0}")]
    JsonError(String),
    #[error("Binary error: {0}")]
    BinaryError(String),
}

#[derive(Error, Debug)]
pub enum RecoverSenderError {
    #[error("Failed to deserialize signature: {0}")]
    SignatureDeserializationError(String),
    #[error("Empty message")]
    EmptyMessage,
    #[error("Failed to recover address: {0}")]
    AddressRecoveryError(String),
}

macro_rules! impl_signed_message {
    ($type:ty) => {
        impl SignedMessage for $type {
            fn signature(&self) -> Vec<u8> {
                self.signature.clone()
            }

            fn nonce(&self) -> Result<u64, MessageError> {
                match &self.body {
                    Some(body) => Ok(body.nonce as u64),
                    None => Err(MessageError::EmptyMessage),
                }
            }

            fn message(&self) -> Result<Vec<u8>, MessageError> {
                let format = MessageFormat::try_from(self.format).unwrap_or(MessageFormat::Binary);

                match &self.body {
                    Some(body) => match format {
                        MessageFormat::Json => format_json_message(body).map_err(|e| match e {
                            JsonFormatError::SerializationError(msg) => {
                                MessageError::JsonError(msg)
                            }
                        }),
                        MessageFormat::Binary => {
                            let proto_bytes = body.encode_to_vec();
                            Ok(proto_bytes)
                        }
                        MessageFormat::UnspecifiedMessageFormat => {
                            let proto_bytes = body.encode_to_vec();
                            Ok(proto_bytes)
                        }
                    },
                    None => Err(MessageError::EmptyMessage),
                }
            }

            fn recover_sender(&self) -> Result<(Address, Vec<u8>), RecoverSenderError> {
                let message = self.message().map_err(|_| RecoverSenderError::EmptyMessage)?;
                let sender = recover_sender_raw(self.signature.clone(), message.clone())?;
                Ok((sender, message))
            }
        }
    };
}

impl_signed_message!(RequestProofRequest);
impl_signed_message!(FulfillProofRequest);

#[allow(clippy::needless_pass_by_value)]
pub fn recover_sender_raw(
    signature: Vec<u8>,
    message: Vec<u8>,
) -> Result<Address, RecoverSenderError> {
    let signature = Signature::try_from(signature.as_slice())
        .map_err(|e| RecoverSenderError::SignatureDeserializationError(e.to_string()))?;

    signature
        .recover_address_from_msg(message)
        .map_err(|e| RecoverSenderError::AddressRecoveryError(e.to_string()))
}
