use sp1_curves::{edwards::WORDS_FIELD_ELEMENT, COMPRESSED_POINT_BYTES, NUM_BYTES_FIELD_ELEMENT};
use sp1_primitives::consts::words_to_bytes_le;

use crate::{
    events::{
        EdDecompressEvent, EdwardsPageProtRecords, MemoryReadRecord, MemoryWriteRecord,
        PrecompileEvent,
    },
    vm::syscall::SyscallRuntime,
    ExecutionMode, SyscallCode, TrapError,
};

/// Check page permissions for edwards decompress. Returns early if permission check fails.
fn trap_edwards_decompress<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>>(
    rt: &mut RT,
    slice_ptr: u64,
) -> (EdwardsPageProtRecords, Option<TrapError>) {
    let mut ret = EdwardsPageProtRecords {
        read_page_prot_records: Vec::new(),
        write_page_prot_records: Vec::new(),
    };

    let (y_page_prot_records, y_error) =
        rt.read_slice_check(slice_ptr + (COMPRESSED_POINT_BYTES as u64), WORDS_FIELD_ELEMENT);
    ret.read_page_prot_records = y_page_prot_records;
    if y_error.is_some() {
        return (ret, y_error);
    }

    rt.increment_clk();
    let (x_page_prot_records, x_error) = rt.write_slice_check(slice_ptr, WORDS_FIELD_ELEMENT);
    ret.write_page_prot_records = x_page_prot_records;
    if x_error.is_some() {
        return (ret, x_error);
    }

    (ret, None)
}

pub(crate) fn edwards_decompress<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>>(
    rt: &mut RT,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, TrapError> {
    let slice_ptr = arg1;
    let sign_bit = arg2;
    assert!(slice_ptr.is_multiple_of(8), "slice_ptr must be 8-byte aligned.");
    assert!(sign_bit <= 1, "Sign bit must be 0 or 1.");

    let clk = rt.core().clk();

    let sign = sign_bit != 0;

    let (page_prot_records, is_trap) = trap_edwards_decompress(rt, slice_ptr);

    // Default values if trap occurs
    let mut y_memory_records_vec: Vec<MemoryReadRecord> = Vec::new();
    let mut x_memory_records_vec: Vec<MemoryWriteRecord> = Vec::new();

    rt.reset_clk(clk);
    if is_trap.is_none() {
        y_memory_records_vec = rt.mr_slice_without_prot(
            slice_ptr + (COMPRESSED_POINT_BYTES as u64),
            WORDS_FIELD_ELEMENT,
        );

        rt.increment_clk();

        // Write decompressed X into slice
        x_memory_records_vec = rt.mw_slice_without_prot(slice_ptr, WORDS_FIELD_ELEMENT);
    }

    if RT::TRACING {
        let (local_mem_access, local_page_prot_access) = rt.postprocess_precompile();

        let y_vec: Vec<_> = y_memory_records_vec.iter().map(|record| record.value).collect();
        let y_memory_records: [MemoryReadRecord; WORDS_FIELD_ELEMENT] =
            if y_memory_records_vec.len() == WORDS_FIELD_ELEMENT {
                y_memory_records_vec.try_into().unwrap()
            } else {
                [MemoryReadRecord::default(); WORDS_FIELD_ELEMENT]
            };
        let y_bytes: [u8; COMPRESSED_POINT_BYTES] = if y_vec.len() == WORDS_FIELD_ELEMENT {
            words_to_bytes_le(&y_vec)
        } else {
            [0u8; COMPRESSED_POINT_BYTES]
        };

        let x_vec: Vec<_> = x_memory_records_vec.iter().map(|record| record.value).collect();
        let x_memory_records: [MemoryWriteRecord; WORDS_FIELD_ELEMENT] =
            if x_memory_records_vec.len() == WORDS_FIELD_ELEMENT {
                x_memory_records_vec.try_into().unwrap()
            } else {
                [MemoryWriteRecord::default(); WORDS_FIELD_ELEMENT]
            };
        let decompressed_x_bytes: [u8; NUM_BYTES_FIELD_ELEMENT] =
            if x_vec.len() == WORDS_FIELD_ELEMENT {
                words_to_bytes_le(&x_vec)
            } else {
                [0u8; NUM_BYTES_FIELD_ELEMENT]
            };

        let event = EdDecompressEvent {
            clk,
            ptr: slice_ptr,
            sign,
            y_bytes,
            decompressed_x_bytes,
            y_memory_records,
            x_memory_records,
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
        rt.add_precompile_event(syscall_code, syscall_event, PrecompileEvent::EdDecompress(event));
    }

    if let Some(err) = is_trap {
        return Err(err);
    }

    Ok(None)
}
