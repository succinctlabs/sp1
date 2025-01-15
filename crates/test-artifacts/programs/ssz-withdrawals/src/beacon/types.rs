use crate::DeserializeError;
use serde;
use serde_with::{serde_as, DisplayFromStr};
use ssz_rs::prelude::{Deserialize, Node, SimpleSerialize, Sized, Vector};

pub type Bytes32 = Node;
pub type BLSPubkey = Vector<u8, 48>;
pub type ExecutionAddress = Vector<u8, 20>;

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct Validator {
    pub pubkey: BLSPubkey,
    pub withdrawal_credentials: Bytes32,
    pub effective_balance: u64,
    pub slashed: bool,
    pub activation_eligibility_epoch: u64,
    pub activation_epoch: u64,
    pub exit_epoch: u64,
    pub withdrawable_epoch: u64,
}

#[serde_as]
#[derive(
    serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug, Default, Clone, SimpleSerialize,
)]
pub struct BeaconBlockHeader {
    #[serde_as(as = "DisplayFromStr")]
    pub slot: u64,
    #[serde_as(as = "DisplayFromStr")]
    pub proposer_index: u64,
    pub parent_root: Bytes32,
    pub state_root: Bytes32,
    pub body_root: Bytes32,
}

#[serde_as]
#[derive(
    serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug, Default, Clone, SimpleSerialize,
)]
#[serde(rename_all = "camelCase")]
pub struct Withdrawal {
    pub index: u64,
    pub validator_index: u64,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub address: ExecutionAddress,
    #[serde_as(as = "DisplayFromStr")]
    pub amount: u64,
}
