//! Septic curve precompile dispatch for the full VM executor.
//!
//! For the POC, the full VM executor path is only required to compile; trace
//! generation for a Septic AIR is not yet implemented. The minimal executor
//! handles the actual computation used by the mock prover.

use crate::{vm::syscall::SyscallRuntime, SyscallCode};

const SEPTIC_POINT_U64_WORDS: usize = 7;
const SEPTIC_SCALAR_U64_WORDS: usize = 4;

pub(crate) fn septic_add<'a, RT: SyscallRuntime<'a>>(
    rt: &mut RT,
    _syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Option<u64> {
    let p_ptr = arg1;
    assert!(p_ptr.is_multiple_of(8), "p_ptr must be 8-byte aligned");
    let q_ptr = arg2;
    assert!(q_ptr.is_multiple_of(8), "q_ptr must be 8-byte aligned");

    let _p = rt.mr_slice_unsafe(SEPTIC_POINT_U64_WORDS);
    let _q = rt.mr_slice(q_ptr, SEPTIC_POINT_U64_WORDS);

    rt.increment_clk();

    let _w = rt.mw_slice(p_ptr, SEPTIC_POINT_U64_WORDS);

    None
}

pub(crate) fn septic_double<'a, RT: SyscallRuntime<'a>>(
    rt: &mut RT,
    _syscall_code: SyscallCode,
    arg1: u64,
    _arg2: u64,
) -> Option<u64> {
    let p_ptr = arg1;
    assert!(p_ptr.is_multiple_of(8), "p_ptr must be 8-byte aligned");

    let _p = rt.mr_slice_unsafe(SEPTIC_POINT_U64_WORDS);
    let _w = rt.mw_slice(p_ptr, SEPTIC_POINT_U64_WORDS);

    None
}

pub(crate) fn septic_scalar_mul<'a, RT: SyscallRuntime<'a>>(
    rt: &mut RT,
    _syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Option<u64> {
    let p_ptr = arg1;
    assert!(p_ptr.is_multiple_of(8), "p_ptr must be 8-byte aligned");
    let scalar_ptr = arg2;
    assert!(scalar_ptr.is_multiple_of(8), "scalar_ptr must be 8-byte aligned");

    let _p = rt.mr_slice_unsafe(SEPTIC_POINT_U64_WORDS);
    let _scalar = rt.mr_slice(scalar_ptr, SEPTIC_SCALAR_U64_WORDS);

    rt.increment_clk();

    let _w = rt.mw_slice(p_ptr, SEPTIC_POINT_U64_WORDS);

    None
}

pub(crate) fn septic_verify<'a, RT: SyscallRuntime<'a>>(
    rt: &mut RT,
    _syscall_code: SyscallCode,
    arg1: u64,
    _arg2: u64,
) -> Option<u64> {
    let buf_ptr = arg1;
    assert!(buf_ptr.is_multiple_of(8), "buf_ptr must be 8-byte aligned");

    let _a = rt.mr_slice_unsafe(SEPTIC_POINT_U64_WORDS);
    let scalars_ptr = buf_ptr + (SEPTIC_POINT_U64_WORDS as u64) * 8;
    let _scalars = rt.mr_slice(scalars_ptr, 2 * SEPTIC_SCALAR_U64_WORDS);

    rt.increment_clk();

    let _w = rt.mw_slice(buf_ptr, SEPTIC_POINT_U64_WORDS);

    None
}
