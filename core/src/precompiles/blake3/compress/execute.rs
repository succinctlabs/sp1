use crate::cpu::{MemoryReadRecord, MemoryWriteRecord};
use crate::precompiles::blake3::{
    Blake3CompressInnerChip, Blake3CompressInnerEvent, BLOCK_SIZE, INPUT_SIZE, OPERATION_COUNT,
    OUTPUT_SIZE, ROUND_COUNT,
};
use crate::precompiles::PrecompileRuntime;
use crate::runtime::Register;

/// The `Blake3CompressInnerChip` is a precompile that implements `blake3_compress_inner`.
impl Blake3CompressInnerChip {
    pub const NUM_CYCLES: u32 =
        (4 * ROUND_COUNT * OPERATION_COUNT * (INPUT_SIZE + OUTPUT_SIZE)) as u32;

    pub fn execute(rt: &mut PrecompileRuntime) -> u32 {
        println!("Blake3CompressInnerChip::execute is running!");
        let state_ptr = rt.register_unsafe(Register::X10);

        // Set the clock back to the original value and begin executing the precompile.
        let saved_clk = rt.clk;
        let saved_state_ptr = state_ptr;
        let mut state_read_records =
            [[[MemoryReadRecord::default(); INPUT_SIZE]; OPERATION_COUNT]; ROUND_COUNT];
        let mut state_write_records =
            [[[MemoryWriteRecord::default(); OUTPUT_SIZE]; OPERATION_COUNT]; ROUND_COUNT];

        for round in 0..ROUND_COUNT {
            for operation in 0..OPERATION_COUNT {
                // Read the state.
                let mut state = [0u32; INPUT_SIZE];
                for i in 0..INPUT_SIZE {
                    let (record, value) = rt.mr(state_ptr + (i as u32) * 4);
                    state_read_records[round][operation][i] = record;
                    state[i] = value;
                    rt.clk += 4;
                }

                // TODO: call g here!
                let results = state;

                // Write the state.
                for i in 0..OUTPUT_SIZE {
                    let record = rt.mw(state_ptr.wrapping_add((i as u32) * 4), results[i]);
                    state_write_records[round][operation][i] = record;
                    rt.clk += 4;
                }
            }
        }

        rt.segment_mut()
            .blake3_compress_inner_events
            .push(Blake3CompressInnerEvent {
                clk: saved_clk,
                state_ptr: saved_state_ptr,
                state_reads: state_read_records,
                state_writes: state_write_records,
            });

        state_ptr
    }
}
