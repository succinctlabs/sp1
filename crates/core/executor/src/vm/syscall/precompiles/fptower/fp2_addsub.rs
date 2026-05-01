use sp1_curves::{
    params::NumWords,
    weierstrass::{FieldType, FpOpField},
};
use typenum::Unsigned;

use crate::{
    events::{
        Fp2AddSubEvent, FpPageProtRecords, MemoryReadRecord, MemoryWriteRecord, PrecompileEvent,
    },
    vm::syscall::SyscallRuntime,
    ExecutionMode, SyscallCode, TrapError,
};

/// Check page permissions for fp2 add/sub. Returns early if permission check fails.
fn trap_fp2_add<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>, P: FpOpField>(
    rt: &mut RT,
    x_ptr: u64,
    y_ptr: u64,
) -> (FpPageProtRecords, Option<TrapError>) {
    let num_words = <P as NumWords>::WordsCurvePoint::USIZE;

    let mut ret = FpPageProtRecords {
        read_page_prot_records: Vec::new(),
        write_page_prot_records: Vec::new(),
    };

    let (y_page_prot_records, y_error) = rt.read_slice_check(y_ptr, num_words);
    ret.read_page_prot_records = y_page_prot_records;
    if y_error.is_some() {
        return (ret, y_error);
    }

    rt.increment_clk();
    let (x_page_prot_records, x_error) = rt.read_write_slice_check(x_ptr, num_words);
    ret.write_page_prot_records = x_page_prot_records;
    if x_error.is_some() {
        return (ret, x_error);
    }

    (ret, None)
}

pub fn fp2_add<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>, P: FpOpField>(
    rt: &mut RT,
    code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, TrapError> {
    let x_ptr = arg1;
    assert!(x_ptr.is_multiple_of(8), "x_ptr must be 8-byte aligned");
    let y_ptr = arg2;
    assert!(y_ptr.is_multiple_of(8), "y_ptr must be 8-byte aligned");

    let clk = rt.core().clk();

    let num_words = <P as NumWords>::WordsCurvePoint::USIZE;

    let (page_prot_records, is_trap) = trap_fp2_add::<M, RT, P>(rt, x_ptr, y_ptr);

    // Default values if trap occurs
    let mut x: Vec<u64> = Vec::new();
    let mut y: Vec<u64> = Vec::new();
    let mut y_memory_records: Vec<MemoryReadRecord> = Vec::new();
    let mut x_memory_records: Vec<MemoryWriteRecord> = Vec::new();

    rt.reset_clk(clk);
    if is_trap.is_none() {
        // Read x (current value that will be overwritten) using mr_slice_unsafe
        // No pointer needed - just reads next num_words from memory
        x = rt.mr_slice_unsafe(num_words);

        y_memory_records = rt.mr_slice_without_prot(y_ptr, num_words);
        y = y_memory_records.iter().map(|record| record.value).collect();

        rt.increment_clk();

        // Write result to x (we don't compute the actual result in tracing mode)
        x_memory_records = rt.mw_slice_without_prot(x_ptr, num_words);
    }

    if RT::TRACING {
        let (local_mem_access, local_page_prot_access) = rt.postprocess_precompile();

        let op = code.fp_op_map();
        let event = Fp2AddSubEvent {
            clk,
            op,
            x_ptr,
            x,
            y_ptr,
            y,
            x_memory_records,
            y_memory_records,
            local_mem_access,
            page_prot_records,
            local_page_prot_access,
        };

        let (syscall_code_key, precompile_event) = match P::FIELD_TYPE {
            FieldType::Bn254 => (
                match code {
                    SyscallCode::BN254_FP2_ADD | SyscallCode::BN254_FP2_SUB => {
                        SyscallCode::BN254_FP2_ADD
                    }
                    _ => unreachable!(),
                },
                PrecompileEvent::Bn254Fp2AddSub(event),
            ),
            FieldType::Bls12381 => (
                match code {
                    SyscallCode::BLS12381_FP2_ADD | SyscallCode::BLS12381_FP2_SUB => {
                        SyscallCode::BLS12381_FP2_ADD
                    }
                    _ => unreachable!(),
                },
                PrecompileEvent::Bls12381Fp2AddSub(event),
            ),
        };

        let syscall_event = rt.syscall_event(
            clk,
            code,
            arg1,
            arg2,
            rt.core().next_pc(),
            rt.core().exit_code(),
            None,
            None,
            is_trap,
        );
        rt.add_precompile_event(syscall_code_key, syscall_event, precompile_event);
    }

    if let Some(err) = is_trap {
        return Err(err);
    }

    Ok(None)
}
