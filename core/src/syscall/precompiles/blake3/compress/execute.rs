use crate::cpu::{MemoryReadRecord, MemoryWriteRecord};
use crate::runtime::Register;
use crate::runtime::Syscall;
use crate::syscall::precompiles::blake3::{
    g_func, Blake3CompressInnerChip, Blake3CompressInnerEvent, G_INDEX, G_INPUT_SIZE,
    G_OUTPUT_SIZE, MSG_SCHEDULE, MSG_SIZE, NUM_MSG_WORDS_PER_CALL, NUM_STATE_WORDS_PER_CALL,
    OPERATION_COUNT, ROUND_COUNT, STATE_SIZE,
};
use crate::syscall::precompiles::SyscallContext;

/// The `Blake3CompressInnerChip` is a precompile that implements `blake3_compress_inner`.
impl Syscall for Blake3CompressInnerChip {
    fn num_extra_cycles(&self) -> u32 {
        (4 * ROUND_COUNT * OPERATION_COUNT * (G_INPUT_SIZE + NUM_STATE_WORDS_PER_CALL)) as u32
    }

    fn execute(&self, rt: &mut SyscallContext) -> u32 {
        println!("Blake3CompressInnerChip::execute is running!");
        let state_ptr = rt.register_unsafe(Register::X10);

        // Set the clock back to the original value and begin executing the precompile.
        let saved_clk = rt.clk;
        let (message_ptr_record, message_ptr) = rt.mr(Register::X11 as u32);
        let saved_state_ptr = state_ptr;
        let mut read_records =
            [[[MemoryReadRecord::default(); G_INPUT_SIZE]; OPERATION_COUNT]; ROUND_COUNT];
        let mut write_records =
            [[[MemoryWriteRecord::default(); G_OUTPUT_SIZE]; OPERATION_COUNT]; ROUND_COUNT];

        let mut output_state_for_debugging = [0u32; STATE_SIZE];
        let mut input_state_for_debugging: [Option<u32>; STATE_SIZE] = [None; STATE_SIZE];
        for round in 0..ROUND_COUNT {
            for operation in 0..OPERATION_COUNT {
                // Read the state.
                let mut state = [0u32; STATE_SIZE];
                let mut input = [0u32; G_INPUT_SIZE];
                for i in 0..NUM_STATE_WORDS_PER_CALL {
                    let index_to_read = G_INDEX[operation][i];
                    let (record, value) = rt.mr(state_ptr + (index_to_read as u32) * 4);
                    read_records[round][operation][i] = record;
                    state[index_to_read] = value;
                    input[i] = value;
                    if input_state_for_debugging[index_to_read].is_none() {
                        input_state_for_debugging[index_to_read] = Some(value);
                    }
                    rt.clk += 4;
                }
                // Read the message.
                let mut message = [0u32; MSG_SIZE];
                for i in 0..NUM_MSG_WORDS_PER_CALL {
                    let index_to_read = MSG_SCHEDULE[round][2 * operation + i];
                    let (record, value) = rt.mr(message_ptr + (index_to_read as u32) * 4);
                    read_records[round][operation][NUM_STATE_WORDS_PER_CALL + i] = record;
                    message[index_to_read] = value;
                    input[i + NUM_STATE_WORDS_PER_CALL] = value;
                    rt.clk += 4;
                }
                println!("round: {:?}", round);
                println!("operation: {:?}", operation);
                println!("state: {:?}", state.map(|x| x.to_le_bytes()));
                println!("message: {:?}\n", message.map(|x| x.to_le_bytes()));

                // TODO: call g here!
                let results = g_func(input);

                // Write the state.
                for i in 0..NUM_STATE_WORDS_PER_CALL {
                    let index_to_write = G_INDEX[operation][i];
                    let record = rt.mw(
                        state_ptr.wrapping_add((index_to_write as u32) * 4),
                        results[i],
                    );
                    write_records[round][operation][i] = record;
                    output_state_for_debugging[index_to_write] = results[i];
                    rt.clk += 4;
                }
            }
        }

        let input = input_state_for_debugging.map(|x| x.unwrap().to_le_bytes());
        let results = output_state_for_debugging.map(|x| x.to_le_bytes());
        println!("state_for_debugging: {:?}", input);
        println!("state_for_debugging: {:?}", results);
        let exp_input_state = [
            [64, 65, 66, 67],
            [68, 69, 70, 71],
            [72, 73, 74, 75],
            [76, 77, 78, 79],
            [80, 81, 82, 83],
            [84, 85, 86, 87],
            [88, 89, 90, 91],
            [92, 93, 94, 95],
            [103, 230, 9, 106],
            [133, 174, 103, 187],
            [114, 243, 110, 60],
            [58, 245, 79, 165],
            [96, 0, 0, 0],
            [0, 0, 0, 0],
            [64, 0, 0, 0],
            [97, 0, 0, 0],
        ];
        assert_eq!(input, exp_input_state, "input state is not as expected");

        let exp_results = [
            [239, 181, 94, 129],
            [58, 124, 80, 104],
            [126, 210, 5, 157],
            [255, 58, 238, 89],
            [252, 106, 170, 12],
            [233, 56, 58, 31],
            [215, 16, 105, 97],
            [11, 229, 238, 73],
            [6, 79, 155, 180],
            [197, 73, 116, 0],
            [127, 22, 16, 39],
            [116, 174, 85, 5],
            [61, 94, 87, 6],
            [236, 10, 36, 238],
            [119, 171, 207, 171],
            [189, 216, 43, 250],
        ];
        assert_eq!(results, exp_results, "output state is not as expected");

        let segment_clk = rt.segment_clk();

        rt.segment_mut()
            .blake3_compress_inner_events
            .push(Blake3CompressInnerEvent {
                segment: segment_clk,
                clk: saved_clk,
                state_ptr: saved_state_ptr,
                reads: read_records,
                writes: write_records,
                message_ptr,
                message_ptr_record,
            });

        state_ptr
    }
}
