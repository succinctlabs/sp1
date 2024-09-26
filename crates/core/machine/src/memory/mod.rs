mod columns;
mod global;
mod local;
mod program;
mod trace;

pub use columns::*;
pub use global::*;
pub use local::*;
pub use program::*;

/// The type of memory chip that is being initialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryChipType {
    Initialize,
    Finalize,
}
