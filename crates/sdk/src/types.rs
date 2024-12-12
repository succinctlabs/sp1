use sp1_stark::MachineVerificationError;
use thiserror::Error;
use std::sync::Arc;
use serde::{Serialize, Deserialize};
use crate::{DEFAULT_TIMEOUT, DEFAULT_CYCLE_LIMIT, CoreSC, InnerSC};

pub use sp1_prover::SP1VerifyingKey;


/// A wrapper around an ELF binary.
///
/// This type is always cheap to clone.
pub enum Elf {
    Slice(&'static [u8]),
    Shared(Arc<[u8]>),
}

mod elf {
   use super::*; 

    impl AsRef<[u8]> for Elf {
        fn as_ref(&self) -> &[u8] {
            match self {
                Self::Slice(slice) => slice,
                Self::Shared(owned) => owned.as_ref(),
            }
        }
    }

    impl std::ops::Deref for Elf {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            self.as_ref()
        }
    }

    impl Clone for Elf {
        fn clone(&self) -> Self {
            match self {
                Self::Slice(slice) => Self::Slice(slice),
                Self::Shared(shared) => Self::Shared(shared.clone()),
            }
        }
    }

    impl From<&'static [u8]> for Elf {
        fn from(slice: &'static [u8]) -> Self {
            Self::Slice(slice)
        }
    }

    impl From<Arc<[u8]>> for Elf {
        fn from(owned: Arc<[u8]>) -> Self {
            Self::Shared(owned)
        }
    }

    impl From<Vec<u8>> for Elf {
        fn from(owned: Vec<u8>) -> Self {
            Self::Shared(owned.into())
        }
    }
}

/// The information necessary to generate a proof for a given RISC-V program.
///
/// This type is always cheap to clone.
pub struct SP1ProvingKey {
    pub(crate) inner: Arc<sp1_prover::SP1ProvingKey>
}

mod proving_key {
    use super::*;

    impl std::ops::Deref for SP1ProvingKey {
        type Target = sp1_prover::SP1ProvingKey;

        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }

    impl Clone for SP1ProvingKey {
        fn clone(&self) -> Self {
            Self { inner: Arc::clone(&self.inner) }
        }
    }

    impl From<sp1_prover::SP1ProvingKey> for SP1ProvingKey {
        fn from(inner: sp1_prover::SP1ProvingKey) -> Self {
            Self { inner: Arc::new(inner) }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SP1ProofWithPublicValues {
    pub(crate) inner: Arc<crate::proof::SP1ProofWithPublicValues>,
}

mod proof {
    use super::*;

    impl From<crate::proof::SP1ProofWithPublicValues> for SP1ProofWithPublicValues {
        fn from(inner: crate::proof::SP1ProofWithPublicValues) -> Self {
            Self { inner: Arc::new(inner) }
        }
    }

    impl Clone for SP1ProofWithPublicValues {
        fn clone(&self) -> Self {
            Self { inner: Arc::clone(&self.inner) }
        }
    }

    impl std::ops::Deref for SP1ProofWithPublicValues {
        type Target = crate::proof::SP1ProofWithPublicValues;

        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }

    impl SP1ProofWithPublicValues {
        pub fn load(path: impl AsRef<std::path::Path>) -> anyhow::Result<Self> {
            let inner = crate::proof::SP1ProofWithPublicValues::load(path)?;

            Ok(Self { inner: Arc::new(inner) })
        }
    }
}

/// The options that every prover type can handle.
pub struct ProofOpts {
    pub mode: Mode,
    pub timeout: u64,
    pub cycle_limit: u64,
}

impl Default for ProofOpts {
    fn default() -> Self {
        Self { mode: Mode::default(), timeout: DEFAULT_TIMEOUT, cycle_limit: DEFAULT_CYCLE_LIMIT }
    }
}

#[cfg(feature = "network-v2")]
use crate::network_v2::ProofMode;

/// The proof mode.
///
/// Plonk and Groth modes enable cheap on-chain verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Core,
    Compressed,
    Plonk,
    Groth16,
}

impl Default for Mode {
    fn default() -> Self {
        Self::Groth16
    }
}

#[cfg(feature = "network-v2")]
impl From<Mode> for ProofMode {
    fn from(value: Mode) -> Self {
        match value {
            Mode::Core => Self::Core,
            Mode::Compressed => Self::Compressed,
            Mode::Plonk => Self::Plonk,
            Mode::Groth16 => Self::Groth16,
        }
    }
}

#[derive(Error, Debug)]
pub enum SP1VerificationError {
    #[error("Invalid public values")]
    InvalidPublicValues,
    #[error("Version mismatch")]
    VersionMismatch(String),
    #[error("Core machine verification error: {0}")]
    Core(MachineVerificationError<CoreSC>),
    #[error("Recursion verification error: {0}")]
    Recursion(MachineVerificationError<InnerSC>),
    #[error("Plonk verification error: {0}")]
    Plonk(anyhow::Error),
    #[error("Groth16 verification error: {0}")]
    Groth16(anyhow::Error),
}
