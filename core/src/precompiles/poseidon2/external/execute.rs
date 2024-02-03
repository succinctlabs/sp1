use crate::{
    cpu::{MemoryReadRecord, MemoryWriteRecord},
    precompiles::{poseidon2::Poseidon2ExternalEvent, PrecompileRuntime},
    runtime::Register,
};

use super::{columns::POSEIDON2_DEFAULT_EXTERNAL_ROUNDS, Poseidon2ExternalChip};

// TODO: I just copied and pasted these from sha as a starting point, so a lot will likely has to
// change.
impl<const N: usize> Poseidon2ExternalChip<N> {
    // TODO: How do I calculate this? I just copied and pasted these from sha as a starting point.
    pub const NUM_CYCLES: u32 = (8 * POSEIDON2_DEFAULT_EXTERNAL_ROUNDS * N) as u32;

    pub fn execute(rt: &mut PrecompileRuntime) -> (u32, Poseidon2ExternalEvent<N>) {
        // Read `w_ptr` from register a0.
        let state_ptr = rt.register_unsafe(Register::X10);

        // Set the clock back to the original value and begin executing the
        // precompile.
        let saved_clk = rt.clk;
        let saved_state_ptr = state_ptr;
        let mut state_read_records =
            [[MemoryReadRecord::default(); N]; POSEIDON2_DEFAULT_EXTERNAL_ROUNDS];
        let mut state_write_records =
            [[MemoryWriteRecord::default(); N]; POSEIDON2_DEFAULT_EXTERNAL_ROUNDS];

        // Execute the "initialize" phase.
        // const H_START_IDX: u32 = 64;
        // let mut hx = [0u32; 8];

        // Read?
        for round in 0..POSEIDON2_DEFAULT_EXTERNAL_ROUNDS {
            let mut input_state = Vec::new();
            for i in 0..N {
                let (record, value) = rt.mr(state_ptr + (i as u32) * 4);
                state_read_records[round][i] = record;
                input_state.push(value);
                // TODO: Remove this debugging statement.
                println!("clk: {} value: {}", rt.clk, value);
                // hx[i] = value;
                rt.clk += 4;
            }
        }

        // Execute the "compress" phase.
        // let mut a = hx[0];
        // let mut b = hx[1];
        // let mut c = hx[2];
        // let mut d = hx[3];
        // let mut e = hx[4];
        // let mut f = hx[5];
        // let mut g = hx[6];
        // let mut h = hx[7];
        // TODO: I think this is where I can read each element in the state and do stuff? Look into
        // this more.
        // for i in 0..N {
        //     //        for i in 0..64 {
        //     // let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        //     // let ch = (e & f) ^ (!e & g);
        //     let (_record, w_i) = rt.mr(state_ptr + i as u32 * 4);
        //     input_state.push(w_i);
        //     // w_i_read_records.push(record);
        //     // let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(w_i);
        //     // let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        //     // let maj = (a & b) ^ (a & c) ^ (b & c);
        //     // let temp2 = s0.wrapping_add(maj);

        //     // h = g;
        //     // g = f;
        //     // f = e;
        //     // e = d.wrapping_add(temp1);
        //     // d = c;
        //     // c = b;
        //     // b = a;
        //     // a = temp1.wrapping_add(temp2);

        //     rt.clk += 4;
        // }
        // }

        // // Execute the "finalize" phase.
        // // let v = [a, b, c, d, e, f, g, h];
        // Write?
        for round in 0..POSEIDON2_DEFAULT_EXTERNAL_ROUNDS {
            for i in 0..N {
                let record = rt.mw(
                    state_ptr.wrapping_add((i as u32) * 4),
                    100 + i as u32, // TODO: Just for fun, i'm putting 200 + i back into the memory.
                );
                state_write_records[round][i] = record;
                rt.clk += 4;
            }
        }

        (
            state_ptr,
            Poseidon2ExternalEvent {
                clk: saved_clk,
                state_ptr: saved_state_ptr,
                state_reads: state_read_records,
                state_writes: state_write_records,
            },
        )
    }
}
