#[cfg(target_os = "zkvm")]
pub mod tests;

#[cfg(target_os = "zkvm")]
mod utils;

#[derive(serde::Serialize, serde::Deserialize)]
pub enum TestName {
    Keccak,
    Sha256,
    Curve25519DalekNg,
    Curve25519Dalek,
    Ed25519Dalek,
    Ed25519Consensus,
    K256,
    P256,
    Secp256k1,
}
