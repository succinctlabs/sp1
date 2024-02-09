use crate::cpu::{MemoryReadRecord, MemoryWriteRecord};
use crate::precompiles::blake3::{
    Blake3CompressInnerChip, Blake3CompressInnerEvent, G_INDEX, G_INPUT_SIZE, G_OUTPUT_SIZE,
    INPUT_SIZE, MSG_SCHEDULE, MSG_SIZE, NUM_MSG_WORDS_PER_CALL, NUM_STATE_WORDS_PER_CALL,
    OPERATION_COUNT, ROUND_COUNT, STATE_SIZE,
};
use crate::precompiles::PrecompileRuntime;
use crate::runtime::Register;

/// The `Blake3CompressInnerChip` is a precompile that implements `blake3_compress_inner`.
impl Blake3CompressInnerChip {
    pub const NUM_CYCLES: u32 =
        (4 * ROUND_COUNT * OPERATION_COUNT * (G_INPUT_SIZE + NUM_STATE_WORDS_PER_CALL)) as u32;

    pub fn execute(rt: &mut PrecompileRuntime) -> u32 {
        println!("Blake3CompressInnerChip::execute is running!");
        let state_ptr = rt.register_unsafe(Register::X10);
        let msg_ptr = state_ptr + 4 * STATE_SIZE as u32;

        // Set the clock back to the original value and begin executing the precompile.
        let saved_clk = rt.clk;
        let saved_state_ptr = state_ptr;
        let mut read_records =
            [[[MemoryReadRecord::default(); G_INPUT_SIZE]; OPERATION_COUNT]; ROUND_COUNT];
        let mut write_records =
            [[[MemoryWriteRecord::default(); G_OUTPUT_SIZE]; OPERATION_COUNT]; ROUND_COUNT];

        for round in 0..ROUND_COUNT {
            for operation in 0..OPERATION_COUNT {
                // Read the state.
                let mut state = [0u32; STATE_SIZE];
                for i in 0..NUM_STATE_WORDS_PER_CALL {
                    let index_to_read = G_INDEX[operation][i];
                    let (record, value) = rt.mr(state_ptr + (index_to_read as u32) * 4);
                    read_records[round][operation][i] = record;
                    state[index_to_read] = value;
                    rt.clk += 4;
                }
                // Read the message.
                let mut message = [0u32; MSG_SIZE];
                for i in 0..NUM_MSG_WORDS_PER_CALL {
                    let index_to_read = MSG_SCHEDULE[round][2 * operation + i];
                    let (record, value) = rt.mr(msg_ptr + (index_to_read as u32) * 4);
                    read_records[round][operation][NUM_STATE_WORDS_PER_CALL + i] = record;
                    message[index_to_read] = value;
                    rt.clk += 4;
                }
                println!("round: {:?}", round);
                println!("operation: {:?}", operation);
                println!("state: {:?}", state);
                println!("message: {:?}\n", message);

                // TODO: call g here!
                let results = state;

                // Write the state.
                for i in 0..NUM_STATE_WORDS_PER_CALL {
                    let index_to_write = G_INDEX[operation][i];
                    let record = rt.mw(
                        state_ptr.wrapping_add((index_to_write as u32) * 4),
                        results[index_to_write],
                    );
                    write_records[round][operation][i] = record;
                    rt.clk += 4;
                }
            }
        }

        let segment_clk = rt.segment_clk();

        rt.segment_mut()
            .blake3_compress_inner_events
            .push(Blake3CompressInnerEvent {
                segment: segment_clk,
                clk: saved_clk,
                state_ptr: saved_state_ptr,
                reads: read_records,
                writes: write_records,
            });

        state_ptr
    }
}
