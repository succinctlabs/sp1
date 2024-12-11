use std::borrow::BorrowMut;

use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use rayon::iter::{ParallelBridge, ParallelIterator};
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, MemInstrEvent},
    ByteOpcode, ExecutionRecord, Opcode, Program,
};
use sp1_primitives::consts::WORD_SIZE;
use sp1_stark::air::MachineAir;

use crate::utils::{next_power_of_two, zeroed_f_vec};

use super::{
    columns::{MemoryInstructionsColumns, NUM_MEMORY_INSTRUCTIONS_COLUMNS},
    MemoryInstructionsChip,
};

impl<F: PrimeField32> MachineAir<F> for MemoryInstructionsChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "MemoryInstrs".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let chunk_size = std::cmp::max((input.memory_instr_events.len()) / num_cpus::get(), 1);
        let nb_rows = input.memory_instr_events.len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_power_of_two(nb_rows, size_log2);
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_MEMORY_INSTRUCTIONS_COLUMNS);

        let blu_events = values
            .chunks_mut(chunk_size * NUM_MEMORY_INSTRUCTIONS_COLUMNS)
            .enumerate()
            .par_bridge()
            .map(|(i, rows)| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                rows.chunks_mut(NUM_MEMORY_INSTRUCTIONS_COLUMNS).enumerate().for_each(
                    |(j, row)| {
                        let idx = i * chunk_size + j;
                        let cols: &mut MemoryInstructionsColumns<F> = row.borrow_mut();

                        if idx < input.memory_instr_events.len() {
                            let event = &input.memory_instr_events[idx];
                            self.event_to_row(event, cols, &mut blu);
                        }
                    },
                );
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_events.iter().collect_vec());

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_MEMORY_INSTRUCTIONS_COLUMNS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.memory_instr_events.is_empty()
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl MemoryInstructionsChip {
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &MemInstrEvent,
        cols: &mut MemoryInstructionsColumns<F>,
        blu: &mut HashMap<ByteLookupEvent, usize>,
    ) {
        cols.shard = F::from_canonical_u32(event.shard);
        assert!(cols.shard != F::zero());
        cols.clk = F::from_canonical_u32(event.clk);
        cols.pc = F::from_canonical_u32(event.pc);
        cols.op_a_value = event.a.into();
        cols.op_b_value = event.b.into();
        cols.op_c_value = event.c.into();
        cols.op_a_0 = F::from_bool(event.op_a_0);

        // Populate memory accesses for reading from memory.
        cols.memory_access.populate(event.mem_access, blu);

        // Populate addr_word and addr_aligned columns.
        let memory_addr = event.b.wrapping_add(event.c);
        let aligned_addr = memory_addr - memory_addr % WORD_SIZE as u32;
        cols.addr_word = memory_addr.into();
        cols.addr_word_range_checker.populate(cols.addr_word, blu);
        cols.addr_aligned = F::from_canonical_u32(aligned_addr);

        // Populate the aa_least_sig_byte_decomp columns.
        assert!(aligned_addr % 4 == 0);
        // Populate memory offsets.
        let addr_ls_two_bits = (memory_addr % WORD_SIZE as u32) as u8;
        cols.addr_ls_two_bits = F::from_canonical_u8(addr_ls_two_bits);
        cols.ls_bits_is_one = F::from_bool(addr_ls_two_bits == 1);
        cols.ls_bits_is_two = F::from_bool(addr_ls_two_bits == 2);
        cols.ls_bits_is_three = F::from_bool(addr_ls_two_bits == 3);

        // Add byte lookup event to verify correct calculation of addr_ls_two_bits.
        blu.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::AND,
            a1: addr_ls_two_bits as u16,
            a2: 0,
            b: cols.addr_word[0].as_canonical_u32() as u8,
            c: 0b11,
        });

        // If it is a load instruction, set the unsigned_mem_val column.
        let mem_value = event.mem_access.value();
        if matches!(event.opcode, Opcode::LB | Opcode::LBU | Opcode::LH | Opcode::LHU | Opcode::LW)
        {
            match event.opcode {
                Opcode::LB | Opcode::LBU => {
                    cols.unsigned_mem_val =
                        (mem_value.to_le_bytes()[addr_ls_two_bits as usize] as u32).into();
                }
                Opcode::LH | Opcode::LHU => {
                    let value = match (addr_ls_two_bits >> 1) % 2 {
                        0 => mem_value & 0x0000FFFF,
                        1 => (mem_value & 0xFFFF0000) >> 16,
                        _ => unreachable!(),
                    };
                    cols.unsigned_mem_val = value.into();
                }
                Opcode::LW => {
                    cols.unsigned_mem_val = mem_value.into();
                }
                _ => unreachable!(),
            }

            // For the signed load instructions, we need to check if the loaded value is negative.
            if matches!(event.opcode, Opcode::LB | Opcode::LH) {
                let most_sig_mem_value_byte = if matches!(event.opcode, Opcode::LB) {
                    cols.unsigned_mem_val.to_u32().to_le_bytes()[0]
                } else {
                    cols.unsigned_mem_val.to_u32().to_le_bytes()[1]
                };

                let most_sig_mem_value_bit = most_sig_mem_value_byte >> 7;
                if most_sig_mem_value_bit == 1 {
                    cols.mem_value_is_neg_not_x0 = F::from_bool(!event.op_a_0);
                }

                cols.most_sig_byte = F::from_canonical_u8(most_sig_mem_value_byte);
                cols.most_sig_bit = F::from_canonical_u8(most_sig_mem_value_bit);

                blu.add_byte_lookup_event(ByteLookupEvent {
                    opcode: ByteOpcode::MSB,
                    a1: most_sig_mem_value_bit as u16,
                    a2: 0,
                    b: most_sig_mem_value_byte,
                    c: 0,
                });
            }

            // Set the `mem_value_is_pos_not_x0` composite flag.
            cols.mem_value_is_pos_not_x0 = F::from_bool(
                ((matches!(event.opcode, Opcode::LB | Opcode::LH)
                    && (cols.most_sig_bit == F::zero()))
                    || matches!(event.opcode, Opcode::LBU | Opcode::LHU | Opcode::LW))
                    && !event.op_a_0,
            )
        }

        cols.is_lb = F::from_bool(matches!(event.opcode, Opcode::LB));
        cols.is_lbu = F::from_bool(matches!(event.opcode, Opcode::LBU));
        cols.is_lh = F::from_bool(matches!(event.opcode, Opcode::LH));
        cols.is_lhu = F::from_bool(matches!(event.opcode, Opcode::LHU));
        cols.is_lw = F::from_bool(matches!(event.opcode, Opcode::LW));
        cols.is_sb = F::from_bool(matches!(event.opcode, Opcode::SB));
        cols.is_sh = F::from_bool(matches!(event.opcode, Opcode::SH));
        cols.is_sw = F::from_bool(matches!(event.opcode, Opcode::SW));

        // Add event to byte lookup for byte range checking each byte in the memory addr
        let addr_bytes = memory_addr.to_le_bytes();
        blu.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::U8Range,
            a1: 0,
            a2: 0,
            b: addr_bytes[1],
            c: addr_bytes[2],
        });

        cols.most_sig_bytes_zero
            .populate_from_field_element(cols.addr_word[1] + cols.addr_word[2] + cols.addr_word[3]);

        if cols.most_sig_bytes_zero.result == F::one() {
            blu.add_byte_lookup_event(ByteLookupEvent {
                opcode: ByteOpcode::LTU,
                a1: 1,
                a2: 0,
                b: 31,
                c: cols.addr_word[0].as_canonical_u32() as u8,
            });
        }
    }
}
