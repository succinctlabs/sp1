use sp1_curves::{params::NumWords, CurveType, EllipticCurve};

use crate::{
    events::{
        EllipticCurveMulEvent, EllipticCurvePageProtRecords, MemoryReadRecord, MemoryWriteRecord,
        PrecompileEvent,
    },
    vm::syscall::SyscallRuntime,
    ExecutionMode, SyscallCode, TrapError,
};
use typenum::Unsigned;

/// Check page permissions for weierstrass mul. Returns early if permission check fails.
fn trap_weierstrass_mul<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>, E: EllipticCurve>(
    rt: &mut RT,
    p_ptr: u64,
    scalar_ptr: u64,
) -> (EllipticCurvePageProtRecords, Option<TrapError>) {
    let num_point_words = <E::BaseField as NumWords>::WordsCurvePoint::USIZE;
    let num_scalar_words = <E::BaseField as NumWords>::WordsFieldElement::USIZE;

    let mut ret = EllipticCurvePageProtRecords {
        read_page_prot_records: Vec::new(),
        write_page_prot_records: Vec::new(),
    };

    let (scalar_page_prot_records, scalar_error) =
        rt.read_slice_check(scalar_ptr, num_scalar_words);
    ret.read_page_prot_records = scalar_page_prot_records;
    if scalar_error.is_some() {
        return (ret, scalar_error);
    }

    rt.increment_clk();
    let (write_page_prot_records, write_error) = rt.read_write_slice_check(p_ptr, num_point_words);
    ret.write_page_prot_records = write_page_prot_records;
    if write_error.is_some() {
        return (ret, write_error);
    }

    (ret, None)
}

/// Tracing-path executor for the Weierstrass scalar-multiplication syscall.
///
/// `arg1` (a0) is a pointer to a point on the curve; the point is overwritten in place with
/// `scalar * p`. `arg2` (a1) is a pointer to a `BigUint` scalar (4 little-endian `u64` limbs
/// for secp256k1).
pub(crate) fn weierstrass_mul<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>, E: EllipticCurve>(
    rt: &mut RT,
    syscall_code: SyscallCode,
    p_ptr: u64,
    scalar_ptr: u64,
) -> Result<Option<u64>, TrapError> {
    if !p_ptr.is_multiple_of(8) || !scalar_ptr.is_multiple_of(8) {
        panic!();
    }

    let clk = rt.core().clk();

    let num_point_words = <E::BaseField as NumWords>::WordsCurvePoint::USIZE;
    let num_scalar_words = <E::BaseField as NumWords>::WordsFieldElement::USIZE;

    let (page_prot_records, is_trap) = trap_weierstrass_mul::<M, RT, E>(rt, p_ptr, scalar_ptr);

    // Default values if trap occurs
    let mut p = Vec::new();
    let mut scalar = Vec::new();
    let mut scalar_memory_records: Vec<MemoryReadRecord> = Vec::new();
    let mut write_record: Vec<MemoryWriteRecord> = Vec::new();

    rt.reset_clk(clk);

    if is_trap.is_none() {
        // Accessed via slice unsafe, so unused.
        p = rt.mr_slice_unsafe(num_point_words);

        scalar_memory_records = rt.mr_slice_without_prot(scalar_ptr, num_scalar_words);
        scalar = scalar_memory_records.iter().map(|r| r.value).collect::<Vec<_>>();

        rt.increment_clk();

        write_record = rt.mw_slice_without_prot(p_ptr, num_point_words);
    }

    if RT::TRACING {
        let (local_mem_access, local_page_prot_access) = rt.postprocess_precompile();

        let event = EllipticCurveMulEvent {
            clk,
            p_ptr,
            p,
            exp_ptr: scalar_ptr,
            exp: scalar,
            p_memory_records: write_record,
            exp_memory_records: scalar_memory_records,
            local_mem_access,
            page_prot_records,
            local_page_prot_access,
        };

        let syscall_event = rt.syscall_event(
            clk,
            syscall_code,
            p_ptr,
            scalar_ptr,
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
                PrecompileEvent::Secp256k1Mul(event),
            ),
            _ => panic!("Unsupported curve"),
        }
    }

    if let Some(err) = is_trap {
        return Err(err);
    }

    Ok(None)
}
