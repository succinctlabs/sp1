#![allow(missing_docs)]

use crate::{ProvingKey, SP1ProvingKey};
use sp1_cuda::CudaProvingKey;
use sp1_primitives::Elf;
use sp1_prover::SP1VerifyingKey;

#[derive(Clone)]
pub enum EnvProvingKey {
    Cpu { pk: SP1ProvingKey, seal: sealed::Seal },
    Cuda { pk: CudaProvingKey, seal: sealed::Seal },
    Mock { pk: SP1ProvingKey, seal: sealed::Seal },
    Light { pk: SP1ProvingKey, seal: sealed::Seal },
}

impl EnvProvingKey {
    pub(crate) const fn cpu(inner: SP1ProvingKey) -> Self {
        Self::Cpu { pk: inner, seal: sealed::Seal::new() }
    }

    pub(crate) const fn cuda(inner: CudaProvingKey) -> Self {
        Self::Cuda { pk: inner, seal: sealed::Seal::new() }
    }

    pub(crate) const fn mock(inner: SP1ProvingKey) -> Self {
        Self::Mock { pk: inner, seal: sealed::Seal::new() }
    }

    pub(crate) const fn light(inner: SP1ProvingKey) -> Self {
        Self::Light { pk: inner, seal: sealed::Seal::new() }
    }
}

impl ProvingKey for EnvProvingKey {
    fn verifying_key(&self) -> &SP1VerifyingKey {
        #[allow(clippy::match_same_arms)]
        match self {
            Self::Cpu { pk, .. } => pk.verifying_key(),
            Self::Cuda { pk, .. } => pk.verifying_key(),
            Self::Mock { pk, .. } => pk.verifying_key(),
            Self::Light { pk, .. } => pk.verifying_key(),
        }
    }

    fn elf(&self) -> &Elf {
        #[allow(clippy::match_same_arms)]
        match self {
            Self::Cpu { pk, .. } => pk.elf(),
            Self::Cuda { pk, .. } => pk.elf(),
            Self::Mock { pk, .. } => pk.elf(),
            Self::Light { pk, .. } => pk.elf(),
        }
    }
}

/// A seal for disallowing direct construction of `EnvProver` proving key.
mod sealed {
    #[derive(Clone)]
    pub struct Seal {
        _private: (),
    }

    impl Seal {
        pub(crate) const fn new() -> Self {
            Self { _private: () }
        }
    }
}
