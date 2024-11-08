mod columns;
mod global;
mod local;
mod program;
mod program_dummy;
mod trace;

pub use columns::*;
pub use global::*;
pub use local::*;
pub use program::*;
pub use program_dummy::*;

/// The type of memory chip that is being initialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryChipType {
    Initialize,
    Finalize,
}
