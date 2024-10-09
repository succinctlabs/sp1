use alloy_primitives::{Address, Signature};
use prost::Message;
use thiserror::Error;

use crate::network_v2::proto::network::{FulfillProofRequest, RequestProofRequest};

#[allow(dead_code)]
pub trait SignedMessage {
    fn signature(&self) -> Vec<u8>;
    fn nonce(&self) -> Result<u64, MessageError>;
    fn message(&self) -> Result<Vec<u8>, MessageError>;
    fn recover_sender(&self) -> Result<Address, RecoverSenderError>;
}

#[derive(Error, Debug)]
pub enum MessageError {
    #[error("Empty message")]
    EmptyMessage,
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
                match &self.body {
                    Some(body) => Ok(body.encode_to_vec()),
                    None => Err(MessageError::EmptyMessage),
                }
            }

            fn recover_sender(&self) -> Result<Address, RecoverSenderError> {
                let message = self.message().map_err(|_| RecoverSenderError::EmptyMessage)?;
                recover_sender_raw(self.signature.clone(), message)
            }
        }
    };
}

impl_signed_message!(RequestProofRequest);
impl_signed_message!(FulfillProofRequest);

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
