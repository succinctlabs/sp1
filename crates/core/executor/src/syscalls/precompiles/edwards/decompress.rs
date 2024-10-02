use std::marker::PhantomData;

use sp1_curves::{
    curve25519_dalek::CompressedEdwardsY,
    edwards::{ed25519::decompress, EdwardsParameters, WORDS_FIELD_ELEMENT},
    COMPRESSED_POINT_BYTES,
};
use sp1_primitives::consts::{bytes_to_words_le, words_to_bytes_le};

use crate::{
    events::{EdDecompressEvent, MemoryReadRecord, MemoryWriteRecord, PrecompileEvent},
    syscalls::{Syscall, SyscallCode, SyscallContext},
};

pub(crate) struct EdwardsDecompressSyscall<E: EdwardsParameters> {
    _phantom: PhantomData<E>,
}

impl<E: EdwardsParameters> EdwardsDecompressSyscall<E> {
    /// Create a new instance of the [`EdwardsDecompressSyscall`].
    pub const fn new() -> Self {
        Self { _phantom: PhantomData }
    }
}

impl<E: EdwardsParameters> Syscall for EdwardsDecompressSyscall<E> {
    fn execute(
        &self,
        rt: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        sign: u32,
    ) -> Option<u32> {
        let start_clk = rt.clk;
        let slice_ptr = arg1;
        assert!(slice_ptr % 4 == 0, "Pointer must be 4-byte aligned.");
        assert!(sign <= 1, "Sign bit must be 0 or 1.");

        let (y_memory_records_vec, y_vec) =
            rt.mr_slice(slice_ptr + (COMPRESSED_POINT_BYTES as u32), WORDS_FIELD_ELEMENT);
        let y_memory_records: [MemoryReadRecord; 8] = y_memory_records_vec.try_into().unwrap();

        let sign_bool = sign != 0;

        let y_bytes: [u8; COMPRESSED_POINT_BYTES] = words_to_bytes_le(&y_vec);

        // Copy bytes into another array so we can modify the last byte and make CompressedEdwardsY,
        // which we'll use to compute the expected X.
        // Re-insert sign bit into last bit of Y for CompressedEdwardsY format
        let mut compressed_edwards_y: [u8; COMPRESSED_POINT_BYTES] = y_bytes;
        compressed_edwards_y[compressed_edwards_y.len() - 1] &= 0b0111_1111;
        compressed_edwards_y[compressed_edwards_y.len() - 1] |= (sign as u8) << 7;

        // Compute actual decompressed X
        let compressed_y = CompressedEdwardsY(compressed_edwards_y);
        let decompressed = decompress(&compressed_y);

        let mut decompressed_x_bytes = decompressed.x.to_bytes_le();
        decompressed_x_bytes.resize(32, 0u8);
        let decompressed_x_words: [u32; WORDS_FIELD_ELEMENT] =
            bytes_to_words_le(&decompressed_x_bytes);

        // Write decompressed X into slice
        let x_memory_records_vec = rt.mw_slice(slice_ptr, &decompressed_x_words);
        let x_memory_records: [MemoryWriteRecord; 8] = x_memory_records_vec.try_into().unwrap();

        let lookup_id = rt.syscall_lookup_id;
        let shard = rt.current_shard();
        let event = EdDecompressEvent {
            lookup_id,
            shard,
            clk: start_clk,
            ptr: slice_ptr,
            sign: sign_bool,
            y_bytes,
            decompressed_x_bytes: decompressed_x_bytes.try_into().unwrap(),
            x_memory_records,
            y_memory_records,
            local_mem_access: rt.postprocess(),
        };
        let syscall_event =
            rt.rt.syscall_event(start_clk, syscall_code.syscall_id(), arg1, sign, event.lookup_id);
        rt.record_mut().add_precompile_event(
            syscall_code,
            syscall_event,
            PrecompileEvent::EdDecompress(event),
        );
        None
    }

    fn num_extra_cycles(&self) -> u32 {
        0
    }
}
