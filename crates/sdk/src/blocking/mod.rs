//! Blocking version of the sp1-sdk `ProverClient`.

mod client;
mod cpu;
mod cuda;
mod env;
mod light;
mod mock;
mod prover;

pub use client::ProverClient;
pub use cpu::{builder::CpuProverBuilder, CpuProver};
pub use cuda::{builder::CudaProverBuilder, CudaProver};
pub use env::EnvProver;
pub use light::LightProver;
pub use mock::MockProver;
pub use prover::{ProveRequest, Prover};

pub use crate::{utils, Elf, SP1ProofMode, SP1PublicValues, SP1Stdin};

use std::{future::Future, sync::LazyLock};

/// Block on a future, and return the result.
///
/// Will panic if run within a tokio runtime. It is advised that you switch to the async api
/// if you are already using the tokio runtime directly.
pub(crate) fn block_on<T>(future: impl Future<Output = T>) -> T {
    RUNTIME.block_on(future)
}

/// Runtime handle, used for running async code in a blocking context.
static RUNTIME: LazyLock<tokio::runtime::Runtime> =
    LazyLock::new(|| tokio::runtime::Runtime::new().unwrap());

#[cfg(all(test, feature = "slow-tests"))]
mod tests {
    use super::*;

    #[rstest::rstest]
    fn test_execute(client: &CpuProver) {
        utils::setup_logger();
        let elf = test_artifacts::FIBONACCI_ELF;
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        let (_, _) = client.execute(elf, stdin).run().unwrap();
    }

    #[rstest::rstest]
    fn test_execute_panic(client: &CpuProver) {
        utils::setup_logger();
        let elf = test_artifacts::PANIC_ELF;
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        client.execute(elf, stdin).run().unwrap();
        // TODO: once the exit code is exposed to the SDK, check its value, both here and elsewhere.
    }

    #[rstest::rstest]
    #[should_panic]
    fn test_cycle_limit_fail(client: &CpuProver) {
        utils::setup_logger();
        let elf = test_artifacts::PANIC_ELF;
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);
        client.execute(elf, stdin).cycle_limit(1).run().unwrap();
    }

    #[rstest::rstest]
    fn test_e2e_core(client: &CpuProver) {
        utils::setup_logger();
        let elf = test_artifacts::FIBONACCI_ELF;
        let pk = client.setup(elf).unwrap();
        let mut stdin = SP1Stdin::new();
        stdin.write(&10usize);

        // Generate proof & verify.
        let mut proof = client.prove(&pk, stdin).run().unwrap();
        client.verify(&proof, &pk.vk, None).unwrap();

        // Test invalid public values.
        proof.public_values = SP1PublicValues::from(&[255, 4, 84]);
        if client.verify(&proof, &pk.vk, None).is_ok() {
            panic!("verified proof with invalid public values")
        }
    }

    #[rstest::fixture]
    #[once]
    fn client() -> CpuProver {
        ProverClient::builder().cpu().build()
    }
}
