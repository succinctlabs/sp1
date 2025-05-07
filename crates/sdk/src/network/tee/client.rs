use super::api::{EventPayload, GetAddressResponse, TEERequest, TEEResponse};

use super::SP1_TEE_VERSION;
use alloy_primitives::Address;
use eventsource_stream::{EventStreamError, Eventsource};
use futures::stream::StreamExt;
use reqwest::{Client as HttpClient, Error as HttpError};

/// Errors that can occur when interacting with the TEE server.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// An error occurred while sending the request.
    #[error("Http Error: {0}")]
    Http(#[from] HttpError),

    /// An error occurred while receiving the response.
    #[error("Event Error: {0}")]
    Event(#[from] EventStreamError<HttpError>),

    /// An error occurred while parsing the response.
    #[error("Failed to parse response: {0}")]
    Parse(#[from] bincode::Error),

    /// An error occurred while decoding the event.
    #[error("Failed to decode event: {0}")]
    Decode(#[from] hex::FromHexError),

    /// An error occurred while the server returned an error.
    #[error("Error received from server: {0}")]
    ServerError(String),

    /// No response was received from the server.
    #[error("No response received")]
    NoResponse,
}

/// Internally, the client uses [SSE](https://en.wikipedia.org/wiki/Server-sent_events)
/// to receive the response from the host, without having to poll the server or worry about
/// the connection being closed.
pub struct Client {
    client: HttpClient,
    url: String,
}

impl Default for Client {
    fn default() -> Self {
        Self::new(crate::network::DEFAULT_TEE_SERVER_URL)
    }
}

impl Client {
    /// Create a new TEE client with the given URL.
    #[must_use]
    pub fn new(url: &str) -> Self {
        Self { client: HttpClient::new(), url: url.to_string() }
    }

    /// Execute a request for an "integrity proof" from the TEE server.
    ///
    /// This function will send a request to the TEE server, and await a response.
    ///
    /// # Errors
    /// - [`ClientError::Http`] - If the request fails to send.
    /// - [`ClientError::Event`] - If the response is not a valid SSE event.
    /// - [`ClientError::Parse`] - If the response fails to be parsed.
    /// - [`ClientError::Decode`] - If the response contains invalid hex.
    /// - [`ClientError::ServerError`] - If the server returns an error.
    /// - [`ClientError::NoResponse`] - If no response is received from the server.
    pub async fn execute(&self, request: TEERequest) -> Result<TEEResponse, ClientError> {
        // The server responds with an SSE stream, and the expected response is the first item.
        let payload: EventPayload = self
            .client
            .post(format!("{}/execute", self.url))
            .header("X-SP1-Tee-Version", SP1_TEE_VERSION)
            .body(bincode::serialize(&request)?)
            .send()
            .await?
            .bytes_stream()
            .eventsource()
            .map(|event| match event {
                Ok(event) => {
                    // The event is a hex encoded payload, which we decode and then deserialize.
                    let decoded = hex::decode(&event.data)?;

                    Ok(bincode::deserialize(&decoded)?)
                }
                Err(e) => Err(ClientError::Event(e)),
            })
            .next()
            .await
            .ok_or(ClientError::NoResponse)??;

        // Everything worked as expected, but the handle the case where execution failed.
        match payload {
            EventPayload::Success(response) => Ok(response),
            // This error type may either be an execution error, or an internal server error.
            // For the former, this should have been checked by the caller locally by executing
            // the program.
            EventPayload::Error(error) => Err(ClientError::ServerError(error)),
        }
    }

    /// Get the address of the TEE server.
    ///
    /// This function will send a request to the TEE server, and await a response.
    ///
    /// # Errors
    /// - [`ClientError::Http`] - If the request fails to send.
    /// - [`ClientError::Parse`] - If the response is not valid.
    pub async fn get_address(&self) -> Result<Address, ClientError> {
        let response = self
            .client
            .get(format!("{}/address", self.url))
            .header("X-SP1-Tee-Version", SP1_TEE_VERSION)
            .send()
            .await?
            .json::<GetAddressResponse>()
            .await?;

        Ok(response.address)
    }

    /// Get the list of signers for the TEE server corresponding to the current SP1 circuit version.
    ///
    /// This function will send a request to the TEE server, and await a response.
    ///
    /// # Errors
    /// - [`ClientError::Http`] - If the request fails to send.
    pub async fn get_signers(&self) -> Result<Vec<Address>, ClientError> {
        let response = self
            .client
            .get(format!("{}/signers", self.url))
            .header("X-SP1-Tee-Version", SP1_TEE_VERSION)
            .send()
            .await?
            .bytes()
            .await?;

        bincode::deserialize(&response).map_err(ClientError::Parse)
    }
}
