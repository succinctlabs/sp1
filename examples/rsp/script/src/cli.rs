use alloy_provider::{network::AnyNetwork, Provider as _, ReqwestProvider};
use clap::Parser;
use url::Url;

/// The arguments for configuring the chain data provider.
#[derive(Debug, Clone, Parser)]
pub struct ProviderArgs {
    /// The rpc url used to fetch data about the block. If not provided, will use the
    /// RPC_{chain_id} env var.
    #[clap(long)]
    rpc_url: Option<Url>,
    /// The chain ID. If not provided, requires the rpc_url argument to be provided.
    #[clap(long)]
    chain_id: Option<u64>,
}

pub struct ProviderConfig {
    pub rpc_url: Option<Url>,
    pub chain_id: u64,
}

impl ProviderArgs {
    pub async fn into_provider(self) -> eyre::Result<ProviderConfig> {
        // We don't need RPC when using cache with known chain ID, so we leave it as `Option<Url>`
        // here and decide on whether to panic later.
        //
        // On the other hand chain ID is always needed.
        let (rpc_url, chain_id) = match (self.rpc_url, self.chain_id) {
            (Some(rpc_url), Some(chain_id)) => (Some(rpc_url), chain_id),
            (None, Some(chain_id)) => {
                match std::env::var(format!("RPC_{}", chain_id)) {
                    Ok(rpc_env_var) => {
                        // We don't always need it but if the value exists it has to be valid.
                        (Some(Url::parse(rpc_env_var.as_str()).expect("invalid rpc url")), chain_id)
                    }
                    Err(_) => {
                        // Not having RPC is okay because we know chain ID.
                        (None, chain_id)
                    }
                }
            }
            (Some(rpc_url), None) => {
                // We can find out about chain ID from RPC.
                let provider: ReqwestProvider<AnyNetwork> =
                    ReqwestProvider::new_http(rpc_url.clone());
                let chain_id = provider.get_chain_id().await?;

                (Some(rpc_url), chain_id)
            }
            (None, None) => {
                eyre::bail!("either --rpc-url or --chain-id must be used")
            }
        };

        Ok(ProviderConfig { rpc_url, chain_id })
    }
}
