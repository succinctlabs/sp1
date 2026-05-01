use sp1_curves::{params::NumWords, CurveType, EllipticCurve};

use crate::{
    events::{
        EllipticCurveAddEvent, EllipticCurvePageProtRecords, MemoryReadRecord, MemoryWriteRecord,
        PrecompileEvent,
    },
    vm::syscall::SyscallRuntime,
    ExecutionMode, SyscallCode, TrapError,
};
use typenum::Unsigned;

/// Check page permissions for weierstrass add. Returns early if permission check fails.
fn trap_weierstrass_add<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>, E: EllipticCurve>(
    rt: &mut RT,
    p_ptr: u64,
    q_ptr: u64,
) -> (EllipticCurvePageProtRecords, Option<TrapError>) {
    let num_words = <E::BaseField as NumWords>::WordsCurvePoint::USIZE;

    let mut ret = EllipticCurvePageProtRecords {
        read_page_prot_records: Vec::new(),
        write_page_prot_records: Vec::new(),
    };

    let (q_page_prot_records, q_error) = rt.read_slice_check(q_ptr, num_words);
    ret.read_page_prot_records = q_page_prot_records;
    if q_error.is_some() {
        return (ret, q_error);
    }

    rt.increment_clk();
    let (write_page_prot_records, write_error) = rt.read_write_slice_check(p_ptr, num_words);
    ret.write_page_prot_records = write_page_prot_records;
    if write_error.is_some() {
        return (ret, write_error);
    }

    (ret, None)
}

pub(crate) fn weierstrass_add<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>, E: EllipticCurve>(
    rt: &mut RT,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, TrapError> {
    let p_ptr = arg1;
    if !p_ptr.is_multiple_of(8) {
        panic!();
    }
    let q_ptr = arg2;
    if !q_ptr.is_multiple_of(8) {
        panic!();
    }

    let clk = rt.core().clk();

    let num_words = <E::BaseField as NumWords>::WordsCurvePoint::USIZE;

    let (page_prot_records, is_trap) = trap_weierstrass_add::<M, RT, E>(rt, p_ptr, q_ptr);

    // Default values if trap occurs
    let mut p = Vec::new();
    let mut q = Vec::new();
    let mut q_memory_records: Vec<MemoryReadRecord> = Vec::new();
    let mut write_record: Vec<MemoryWriteRecord> = Vec::new();

    rt.reset_clk(clk);
    if is_trap.is_none() {
        // Accessed via slice unsafe, so unused.
        p = rt.mr_slice_unsafe(num_words);

        q_memory_records = rt.mr_slice_without_prot(q_ptr, num_words);
        q = q_memory_records.iter().map(|r| r.value).collect::<Vec<_>>();

        rt.increment_clk();

        write_record = rt.mw_slice_without_prot(p_ptr, num_words);
    }

    if RT::TRACING {
        let (local_mem_access, local_page_prot_access) = rt.postprocess_precompile();

        let event = EllipticCurveAddEvent {
            clk,
            p_ptr,
            p,
            q_ptr,
            q,
            p_memory_records: write_record,
            q_memory_records,
            local_mem_access,
            page_prot_records,
            local_page_prot_access,
        };

        let syscall_event = rt.syscall_event(
            clk,
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
            CurveType::Secp256k1 => rt.add_precompile_event(
                syscall_code,
                syscall_event,
                PrecompileEvent::Secp256k1Add(event),
            ),
            CurveType::Bn254 => {
                rt.add_precompile_event(
                    syscall_code,
                    syscall_event,
                    PrecompileEvent::Bn254Add(event),
                );
            }
            CurveType::Bls12381 => rt.add_precompile_event(
                syscall_code,
                syscall_event,
                PrecompileEvent::Bls12381Add(event),
            ),
            CurveType::Secp256r1 => rt.add_precompile_event(
                syscall_code,
                syscall_event,
                PrecompileEvent::Secp256r1Add(event),
            ),
            _ => panic!("Unsupported curve"),
        }
    }

    if let Some(err) = is_trap {
        return Err(err);
    }

    Ok(None)
}
