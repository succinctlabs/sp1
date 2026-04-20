use crate::events::{EllipticCurveDoubleEvent, MemoryWriteRecord, PageProtRecord, PrecompileEvent};
use sp1_curves::{params::NumWords, CurveType, EllipticCurve};

use crate::{vm::syscall::SyscallRuntime, ExecutionMode, SyscallCode, TrapError};
use typenum::Unsigned;

/// Check page permissions for weierstrass double. Returns early if permission check fails.
fn trap_weierstrass_double<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>, E: EllipticCurve>(
    rt: &mut RT,
    p_ptr: u64,
) -> (Vec<PageProtRecord>, Option<TrapError>) {
    let num_words = <E::BaseField as NumWords>::WordsCurvePoint::USIZE;
    rt.read_write_slice_check(p_ptr, num_words)
}

pub(crate) fn weierstrass_double<
    'a,
    M: ExecutionMode,
    RT: SyscallRuntime<'a, M>,
    E: EllipticCurve,
>(
    rt: &mut RT,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, TrapError> {
    let p_ptr: u64 = arg1;
    assert!(p_ptr.is_multiple_of(8), "p_ptr must be 8-byte aligned");

    let clk = rt.core().clk();

    let num_words = <E::BaseField as NumWords>::WordsCurvePoint::USIZE;

    let (p_page_prot_records, is_trap) = trap_weierstrass_double::<M, RT, E>(rt, p_ptr);

    // Default values if trap occurs
    let mut p = Vec::new();
    let mut p_memory_records: Vec<MemoryWriteRecord> = Vec::new();

    if is_trap.is_none() {
        p = rt.mr_slice_unsafe(num_words);
        p_memory_records = rt.mw_slice_without_prot(p_ptr, num_words);
    }

    rt.reset_clk(clk);
    if RT::TRACING {
        let (local_mem_access, local_page_prot_access) = rt.postprocess_precompile();

        let event = EllipticCurveDoubleEvent {
            clk,
            p_ptr,
            p,
            p_memory_records,
            local_mem_access,
            write_slice_page_prot_access: p_page_prot_records,
            local_page_prot_access,
        };

        let syscall_event = rt.syscall_event(
            rt.core().clk(),
            syscall_code,
            arg1,
            arg2,
            rt.core().next_pc(),
            rt.core().exit_code(),
            None,
            None,
            is_trap,
        );

        match E::CURVE_TYPE {
            CurveType::Secp256k1 => {
                rt.add_precompile_event(
                    syscall_code,
                    syscall_event,
                    PrecompileEvent::Secp256k1Double(event),
                );
            }
            CurveType::Secp256r1 => rt.add_precompile_event(
                syscall_code,
                syscall_event,
                PrecompileEvent::Secp256r1Double(event),
            ),
            CurveType::Bn254 => {
                rt.add_precompile_event(
                    syscall_code,
                    syscall_event,
                    PrecompileEvent::Bn254Double(event),
                );
            }
            CurveType::Bls12381 => {
                rt.add_precompile_event(
                    syscall_code,
                    syscall_event,
                    PrecompileEvent::Bls12381Double(event),
                );
            }
            _ => panic!("Unsupported curve"),
        }
    }

    if let Some(err) = is_trap {
        return Err(err);
    }

    Ok(None)
}
