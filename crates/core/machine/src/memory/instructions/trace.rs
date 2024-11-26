use std::{array, borrow::BorrowMut};

use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use rayon::iter::{ParallelBridge, ParallelIterator};
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, MemInstrEvent},
    ByteOpcode, ExecutionRecord, Opcode, Program, DEFAULT_PC_INC,
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
        "MemoryInstructions".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let chunk_size = std::cmp::max((input.memory_instr_events.len()) / num_cpus::get(), 1);
        let nb_rows = input.memory_instr_events.len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_power_of_two(nb_rows, size_log2);
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_MEMORY_INSTRUCTIONS_COLUMNS);

        values
            .chunks_mut(chunk_size * NUM_MEMORY_INSTRUCTIONS_COLUMNS)
            .enumerate()
            .par_bridge()
            .for_each(|(i, rows)| {
                rows.chunks_mut(NUM_MEMORY_INSTRUCTIONS_COLUMNS).enumerate().for_each(
                    |(j, row)| {
                        let idx = i * chunk_size + j;
                        let cols: &mut MemoryInstructionsColumns<F> = row.borrow_mut();

                        if idx < input.memory_instr_events.len() {
                            let mut byte_lookup_events = Vec::new();
                            let event = &input.memory_instr_events[idx];
                            self.event_to_row(
                                event,
                                cols,
                                &input.nonce_lookup,
                                &mut byte_lookup_events,
                            );
                        }
                    },
                );
            });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_MEMORY_INSTRUCTIONS_COLUMNS)
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let chunk_size = std::cmp::max((input.memory_instr_events.len()) / num_cpus::get(), 1);

        let blu_batches = input
            .memory_instr_events
            .chunks(chunk_size)
            .par_bridge()
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = [F::zero(); NUM_MEMORY_INSTRUCTIONS_COLUMNS];
                    let cols: &mut MemoryInstructionsColumns<F> = row.as_mut_slice().borrow_mut();
                    self.event_to_row(event, cols, &input.nonce_lookup, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.memory_instr_events.is_empty()
        }
    }
}

impl MemoryInstructionsChip {
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &MemInstrEvent,
        cols: &mut MemoryInstructionsColumns<F>,
        nonce_lookup: &[u32],
        byte_lookup_events: &mut impl ByteRecord,
    ) {
        cols.shard = F::from_canonical_u32(event.shard);
        assert!(cols.shard != F::zero());
        cols.clk = F::from_canonical_u32(event.clk);
        cols.pc = F::from_canonical_u32(event.pc);
        cols.next_pc = F::from_canonical_u32(event.pc + DEFAULT_PC_INC);
        cols.op_a_value = event.a.into();
        cols.op_b_value = event.b.into();
        cols.op_c_value = event.c.into();
        cols.op_a_0 = F::from_bool(event.op_a_0);

        // Populate memory accesses for reading from memory.
        cols.memory_access.populate(event.mem_access, byte_lookup_events);

        // Populate addr_word and addr_aligned columns.
        let memory_addr = event.b.wrapping_add(event.c);
        let aligned_addr = memory_addr - memory_addr % WORD_SIZE as u32;
        cols.addr_word = memory_addr.into();
        cols.addr_word_range_checker.populate(memory_addr);
        cols.addr_aligned = F::from_canonical_u32(aligned_addr);

        // Populate the aa_least_sig_byte_decomp columns.
        assert!(aligned_addr % 4 == 0);
        let aligned_addr_ls_byte = (aligned_addr & 0x000000FF) as u8;
        let bits: [bool; 8] = array::from_fn(|i| aligned_addr_ls_byte & (1 << i) != 0);
        cols.aa_least_sig_byte_decomp = array::from_fn(|i| F::from_bool(bits[i + 2]));
        cols.addr_word_nonce = F::from_canonical_u32(
            nonce_lookup.get(event.memory_add_lookup_id.0 as usize).copied().unwrap_or_default(),
        );

        // Populate memory offsets.
        let addr_offset = (memory_addr % WORD_SIZE as u32) as u8;
        cols.addr_offset = F::from_canonical_u8(addr_offset);
        cols.offset_is_one = F::from_bool(addr_offset == 1);
        cols.offset_is_two = F::from_bool(addr_offset == 2);
        cols.offset_is_three = F::from_bool(addr_offset == 3);

        // If it is a load instruction, set the unsigned_mem_val column.
        let mem_value = event.mem_access.value();
        if matches!(event.opcode, Opcode::LB | Opcode::LBU | Opcode::LH | Opcode::LHU | Opcode::LW)
        {
            match event.opcode {
                Opcode::LB | Opcode::LBU => {
                    cols.unsigned_mem_val =
                        (mem_value.to_le_bytes()[addr_offset as usize] as u32).into();
                }
                Opcode::LH | Opcode::LHU => {
                    let value = match (addr_offset >> 1) % 2 {
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

                for i in (0..8).rev() {
                    cols.most_sig_byte_decomp[i] =
                        F::from_canonical_u8(most_sig_mem_value_byte >> i & 0x01);
                }
                if cols.most_sig_byte_decomp[7] == F::one() {
                    cols.mem_value_is_neg_not_x0 = F::from_bool(!event.op_a_0);
                    cols.unsigned_mem_val_nonce = F::from_canonical_u32(
                        nonce_lookup
                            .get(event.memory_sub_lookup_id.0 as usize)
                            .copied()
                            .unwrap_or_default(),
                    );
                }
            }

            // Set the `mem_value_is_pos_not_x0` composite flag.
            cols.mem_value_is_pos_not_x0 = F::from_bool(
                ((matches!(event.opcode, Opcode::LB | Opcode::LH)
                    && (cols.most_sig_byte_decomp[7] == F::zero()))
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
        for byte_pair in addr_bytes.chunks_exact(2) {
            byte_lookup_events.add_byte_lookup_event(ByteLookupEvent {
                opcode: ByteOpcode::U8Range,
                a1: 0,
                a2: 0,
                b: byte_pair[0],
                c: byte_pair[1],
            });
        }
    }
}
