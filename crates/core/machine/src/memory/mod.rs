mod bump;
mod consistency;
mod instructions;
mod local;
mod merkle;
mod page_prot;
mod page_prot_local;

pub use bump::*;
pub use consistency::*;
pub use instructions::*;
pub use local::*;
pub use merkle::*;
pub use page_prot::*;
pub use page_prot_local::*;

/// The type of global/local memory chip that is being initialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryChipType {
    Initialize,
    Finalize,
}
