use sp1_curves::EllipticCurve;

use crate::{vm::syscall::SyscallRuntime, ExecutionMode, SyscallCode, TrapError};

/// Tracing-path executor for the Weierstrass scalar-multiplication syscall.
///
/// `arg1` (a0) is a pointer to a point on the curve; the point is overwritten in place with
/// `scalar * p`. `arg2` (a1) is a pointer to a `BigUint` scalar (4 little-endian `u64` limbs
/// for secp256k1).
pub(crate) fn weierstrass_mul<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>, E: EllipticCurve>(
    _rt: &mut RT,
    _syscall_code: SyscallCode,
    _p_ptr: u64,
    _scalar_ptr: u64,
) -> Result<Option<u64>, TrapError> {
    todo!()
}
