mod consistency;
mod global;
mod instructions;
mod local;
mod program;

pub use consistency::*;
pub use global::*;
pub use instructions::*;
pub use local::*;
pub use program::*;

/// The type of global/local memory chip that is being initialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryChipType {
    Initialize,
    Finalize,
}
