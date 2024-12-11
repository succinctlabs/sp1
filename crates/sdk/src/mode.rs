use crate::proof::SP1ProofKind;

#[cfg(feature = "network-v2")]
use crate::network_v2::proto::ProofMode;

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

// impl From<SP1ProofKind> for Mode {
//     fn from(value: SP1ProofKind) -> Self {
//         match value {
//             SP1ProofKind::Core => Self::Core,
//             SP1ProofKind::Compressed => Self::Compressed,
//             SP1ProofKind::Plonk => Self::Plonk,
//             SP1ProofKind::Groth16 => Self::Groth16,
//         }
//     }
// }

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
