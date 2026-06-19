//! Mirror of `zkvm_status` from `zkvm_accelerators.h`.

/// Status codes returned by zkVM accelerator functions. Mirrors the C `enum
/// zkvm_status`: `ZKVM_EOK = 0`, `ZKVM_EFAIL = -1`. `extern "C"` functions in
/// this crate return [`i32`] (the underlying enum width) directly to keep the
/// ABI byte-for-byte identical regardless of how clang/gcc widen the enum.
#[repr(i32)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ZkvmStatus {
    Ok = 0,
    Fail = -1,
}

impl ZkvmStatus {
    #[inline]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

pub const ZKVM_EOK: i32 = 0;
pub const ZKVM_EFAIL: i32 = -1;
