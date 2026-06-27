mod bump;
mod consistency;
mod global;
pub mod instructions;
mod local;
mod page_prot;
mod page_prot_global;
mod page_prot_local;

pub use bump::*;
pub use consistency::*;
pub use global::*;
pub use instructions::*;
pub use local::*;
pub use page_prot::*;
pub use page_prot_global::*;
pub use page_prot_local::*;

/// The type of global/local memory chip that is being initialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryChipType {
    Initialize,
    Finalize,
}
