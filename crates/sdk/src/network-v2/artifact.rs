use crate::network_v2::proto::artifact::{
    artifact_store_client::ArtifactStoreClient, CreateArtifactRequest,
};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use anyhow::Result;
use serde::Serialize;
use tonic::transport::Channel;

pub async fn create_artifact_with_content<T: Serialize>(
    store: &mut ArtifactStoreClient<Channel>,
    signer: &PrivateKeySigner,
    item: &T,
) -> Result<String> {
    let signature = signer.sign_message_sync("create_artifact".as_bytes())?;
    let request = CreateArtifactRequest { signature: signature.as_bytes().to_vec() };
    let response = store.create_artifact(request).await?.into_inner();

    let presigned_url = response.artifact_presigned_url;
    let uri = response.artifact_uri;

    let client = reqwest::Client::new();
    let response = client.put(&presigned_url).body(bincode::serialize::<T>(item)?).send().await?;

    assert!(response.status().is_success());

    Ok(uri)
}
