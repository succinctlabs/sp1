use sp1_curves::EllipticCurve;
use sp1_jit::{Interrupt, SyscallContext};

/// Execute a weierstrass decompress syscall.
#[allow(clippy::extra_unused_type_parameters)]
pub(crate) fn weierstrass_decompress_syscall<E: EllipticCurve>(
    _ctx: &mut impl SyscallContext,
    _slice_ptr: u64,
    _sign_bit: u64,
) -> Result<Option<u64>, Interrupt> {
    panic!("This method should be deprecated.");
}
