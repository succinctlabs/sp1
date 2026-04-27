use sp1_sdk::ProverClient;

#[tokio::main]
async fn main() {
    let client = ProverClient::from_env().await;
}
