use sp1_curves::EllipticCurve;
use sp1_jit::{Interrupt, SyscallContext};

/// Execute a Weierstrass scalar-multiplication syscall.
///
/// `p_ptr` (arg1, a0) is a pointer to a point on the curve. The point is overwritten
/// in place with `scalar * p`.
///
/// `scalar_ptr` (arg2, a1) is a pointer to a `BigUint` scalar, laid out as 4 little-endian
/// `u64` limbs for secp256k1.
pub(crate) unsafe fn weierstrass_mul_assign_syscall<E: EllipticCurve>(
    ctx: &mut impl SyscallContext,
    p_ptr: u64,
    scalar_ptr: u64,
) -> Result<Option<u64>, Interrupt> {
    crate::minimal::precompiles::ec::ec_mul::<E>(ctx, p_ptr, scalar_ptr).map(|()| None)
}
