#![allow(clippy::all)]
#![allow(missing_docs)]
#![allow(clippy::pedantic)]

#[rustfmt::skip]
pub mod artifact;

// Export both auction and base proto modules directly for runtime selection.
#[rustfmt::skip]
pub mod auction {
    #[rustfmt::skip]
    pub mod network;
    #[rustfmt::skip]
    pub mod types;
}

#[rustfmt::skip]
pub mod base {
    #[rustfmt::skip]
    pub mod network;
    #[rustfmt::skip]
    pub mod types;
}

// Export both auction and base types for runtime selection.
#[rustfmt::skip]
pub use self::auction::{network as auction_network, types as auction_types};
#[rustfmt::skip]
pub use self::base::{network as base_network, types as base_types};

// Default re-exports for backwards compatibility - using auction as default.
#[rustfmt::skip]
pub use self::auction::{network, types};

// Unified response types for runtime proto switching.
#[derive(Debug, Clone)]
pub enum GetNonceResponse {
    Auction(auction_types::GetNonceResponse),
    Base(base_types::GetNonceResponse),
}

#[derive(Debug, Clone)]
pub enum GetBalanceResponse {
    Auction(auction_types::GetBalanceResponse),
    Base(base_types::GetBalanceResponse),
}

#[derive(Debug, Clone)]
pub enum GetProgramResponse {
    Auction(auction_types::GetProgramResponse),
    Base(base_types::GetProgramResponse),
}

#[derive(Debug, Clone)]
pub enum RequestProofResponse {
    Auction(auction_types::RequestProofResponse),
    Base(base_types::RequestProofResponse),
}

#[derive(Debug, Clone)]
pub enum GetProofRequestStatusResponse {
    Auction(auction_types::GetProofRequestStatusResponse),
    Base(base_types::GetProofRequestStatusResponse),
}

#[derive(Debug, Clone)]
pub enum GetFilteredProofRequestsResponse {
    Auction(auction_types::GetFilteredProofRequestsResponse),
    Base(base_types::GetFilteredProofRequestsResponse),
}

// Implement From traits for seamless conversion.
impl From<auction_types::GetNonceResponse> for GetNonceResponse {
    fn from(response: auction_types::GetNonceResponse) -> Self {
        Self::Auction(response)
    }
}

impl From<base_types::GetNonceResponse> for GetNonceResponse {
    fn from(response: base_types::GetNonceResponse) -> Self {
        Self::Base(response)
    }
}

impl From<auction_types::GetBalanceResponse> for GetBalanceResponse {
    fn from(response: auction_types::GetBalanceResponse) -> Self {
        Self::Auction(response)
    }
}

impl From<base_types::GetBalanceResponse> for GetBalanceResponse {
    fn from(response: base_types::GetBalanceResponse) -> Self {
        Self::Base(response)
    }
}

impl From<auction_types::GetProgramResponse> for GetProgramResponse {
    fn from(response: auction_types::GetProgramResponse) -> Self {
        Self::Auction(response)
    }
}

impl From<base_types::GetProgramResponse> for GetProgramResponse {
    fn from(response: base_types::GetProgramResponse) -> Self {
        Self::Base(response)
    }
}

impl From<auction_types::RequestProofResponse> for RequestProofResponse {
    fn from(response: auction_types::RequestProofResponse) -> Self {
        Self::Auction(response)
    }
}

impl From<base_types::RequestProofResponse> for RequestProofResponse {
    fn from(response: base_types::RequestProofResponse) -> Self {
        Self::Base(response)
    }
}

impl From<auction_types::GetProofRequestStatusResponse> for GetProofRequestStatusResponse {
    fn from(response: auction_types::GetProofRequestStatusResponse) -> Self {
        Self::Auction(response)
    }
}

impl From<base_types::GetProofRequestStatusResponse> for GetProofRequestStatusResponse {
    fn from(response: base_types::GetProofRequestStatusResponse) -> Self {
        Self::Base(response)
    }
}

impl From<auction_types::GetFilteredProofRequestsResponse> for GetFilteredProofRequestsResponse {
    fn from(response: auction_types::GetFilteredProofRequestsResponse) -> Self {
        Self::Auction(response)
    }
}

impl From<base_types::GetFilteredProofRequestsResponse> for GetFilteredProofRequestsResponse {
    fn from(response: base_types::GetFilteredProofRequestsResponse) -> Self {
        Self::Base(response)
    }
}

// Helper methods for extracting common fields.
impl GetNonceResponse {
    pub fn nonce(&self) -> u64 {
        match self {
            Self::Auction(response) => response.nonce,
            Self::Base(response) => response.nonce,
        }
    }
}

impl GetBalanceResponse {
    pub fn balance(&self) -> &str {
        match self {
            Self::Auction(response) => &response.amount,
            Self::Base(response) => &response.amount,
        }
    }
}

impl GetProgramResponse {
    pub fn program_hash(&self) -> &[u8] {
        match self {
            Self::Auction(response) => response.program.as_ref().map(|p| p.vk_hash.as_slice()).unwrap_or(&[]),
            Self::Base(response) => response.program.as_ref().map(|p| p.vk_hash.as_slice()).unwrap_or(&[]),
        }
    }
    
    pub fn program_uri(&self) -> &str {
        match self {
            Self::Auction(response) => response.program.as_ref().map(|p| p.program_uri.as_str()).unwrap_or(""),
            Self::Base(response) => response.program.as_ref().map(|p| p.program_uri.as_str()).unwrap_or(""),
        }
    }
}

impl RequestProofResponse {
    pub fn request_id(&self) -> &[u8] {
        match self {
            Self::Auction(response) => response.body.as_ref().map(|b| b.request_id.as_slice()).unwrap_or(&[]),
            Self::Base(response) => response.body.as_ref().map(|b| b.request_id.as_slice()).unwrap_or(&[]),
        }
    }

    pub fn tx_hash(&self) -> &[u8] {
        match self {
            Self::Auction(response) => &response.tx_hash,
            Self::Base(response) => &response.tx_hash,
        }
    }

    pub fn body(&self) -> Option<&auction_types::RequestProofResponseBody> {
        match self {
            Self::Auction(response) => response.body.as_ref(),
            Self::Base(_) => None, // Base doesn't have the same body structure.
        }
    }
}

impl GetProofRequestStatusResponse {
    pub fn fulfillment_status(&self) -> i32 {
        match self {
            Self::Auction(response) => response.fulfillment_status,
            Self::Base(response) => response.fulfillment_status,
        }
    }

    pub fn execution_status(&self) -> i32 {
        match self {
            Self::Auction(response) => response.execution_status,
            Self::Base(response) => response.execution_status,
        }
    }

    pub fn deadline(&self) -> u64 {
        match self {
            Self::Auction(response) => response.deadline,
            Self::Base(response) => response.deadline,
        }
    }

    pub fn proof_uri(&self) -> Option<&str> {
        match self {
            Self::Auction(response) => response.proof_uri.as_deref(),
            Self::Base(response) => response.proof_uri.as_deref(),
        }
    }
}

// Auction-only response types.
#[derive(Debug, Clone)]
pub enum CancelRequestResponse {
    Auction(auction_types::CancelRequestResponse),
    Unsupported,
}

#[derive(Debug, Clone)]
pub enum GetProofRequestParamsResponse {
    Auction(auction_types::GetProofRequestParamsResponse),
    Unsupported,
}

impl From<auction_types::CancelRequestResponse> for CancelRequestResponse {
    fn from(response: auction_types::CancelRequestResponse) -> Self {
        Self::Auction(response)
    }
}

impl From<auction_types::GetProofRequestParamsResponse> for GetProofRequestParamsResponse {
    fn from(response: auction_types::GetProofRequestParamsResponse) -> Self {
        Self::Auction(response)
    }
}
