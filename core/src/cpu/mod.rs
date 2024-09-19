pub mod air;
pub mod columns;
pub mod event;
pub mod trace;

pub use event::*;

/// The maximum log degree of the CPU chip to avoid lookup multiplicity overflow.
pub const MAX_CPU_LOG_DEGREE: usize = 22;

/// A chip that implements the CPU.
#[derive(Default)]
pub struct CpuChip;

#[cfg(target_os = "zkvm")]
mod random_shim {
    use getrandom::register_custom_getrandom;

    register_custom_getrandom!(return_err);

    pub fn return_err(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
        Err(getrandom::Error::UNEXPECTED)
    }
}
