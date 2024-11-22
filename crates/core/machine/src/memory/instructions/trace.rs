use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use sp1_core_executor::ExecutionRecord;
use sp1_stark::air::MachineAir;

use super::MemoryInstructionsChip;

impl<F: PrimeField32> MachineAir<F> for MemoryInstructionsChip {
    type Record = ExecutionRecord;

    type Program = Self::Program;

    fn name(&self) -> String {
        "MemoryInstructions".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Populate addr_word and addr_aligned columns.
        let memory_columns = cols.opcode_specific_columns.memory_mut();
        let memory_addr = event.b.wrapping_add(event.c);
        let aligned_addr = memory_addr - memory_addr % WORD_SIZE as u32;
        memory_columns.addr_word = memory_addr.into();
        memory_columns.addr_word_range_checker.populate(memory_addr);
        memory_columns.addr_aligned = F::from_canonical_u32(aligned_addr);

        // Populate the aa_least_sig_byte_decomp columns.
        assert!(aligned_addr % 4 == 0);
        let aligned_addr_ls_byte = (aligned_addr & 0x000000FF) as u8;
        let bits: [bool; 8] = array::from_fn(|i| aligned_addr_ls_byte & (1 << i) != 0);
        memory_columns.aa_least_sig_byte_decomp = array::from_fn(|i| F::from_bool(bits[i + 2]));
        memory_columns.addr_word_nonce = F::from_canonical_u32(
            nonce_lookup.get(event.memory_add_lookup_id.0 as usize).copied().unwrap_or_default(),
        );

        // Populate memory offsets.
        let addr_offset = (memory_addr % WORD_SIZE as u32) as u8;
        memory_columns.addr_offset = F::from_canonical_u8(addr_offset);
        memory_columns.offset_is_one = F::from_bool(addr_offset == 1);
        memory_columns.offset_is_two = F::from_bool(addr_offset == 2);
        memory_columns.offset_is_three = F::from_bool(addr_offset == 3);

        // If it is a load instruction, set the unsigned_mem_val column.
        let mem_value = event.memory_record.unwrap().value();
        if matches!(
            instruction.opcode,
            Opcode::LB | Opcode::LBU | Opcode::LH | Opcode::LHU | Opcode::LW
        ) {
            match instruction.opcode {
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
            if matches!(instruction.opcode, Opcode::LB | Opcode::LH) {
                let most_sig_mem_value_byte = if matches!(instruction.opcode, Opcode::LB) {
                    cols.unsigned_mem_val.to_u32().to_le_bytes()[0]
                } else {
                    cols.unsigned_mem_val.to_u32().to_le_bytes()[1]
                };

                for i in (0..8).rev() {
                    memory_columns.most_sig_byte_decomp[i] =
                        F::from_canonical_u8(most_sig_mem_value_byte >> i & 0x01);
                }
                if memory_columns.most_sig_byte_decomp[7] == F::one() {
                    cols.mem_value_is_neg_not_x0 = F::from_bool(instruction.op_a != (X0 as u8));
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
                ((matches!(instruction.opcode, Opcode::LB | Opcode::LH)
                    && (memory_columns.most_sig_byte_decomp[7] == F::zero()))
                    || matches!(instruction.opcode, Opcode::LBU | Opcode::LHU | Opcode::LW))
                    && instruction.op_a != (X0 as u8),
            );
        }

        // Add event to byte lookup for byte range checking each byte in the memory addr
        let addr_bytes = memory_addr.to_le_bytes();
        for byte_pair in addr_bytes.chunks_exact(2) {
            blu_events.add_byte_lookup_event(ByteLookupEvent {
                shard,
                opcode: ByteOpcode::U8Range,
                a1: 0,
                a2: 0,
                b: byte_pair[0],
                c: byte_pair[1],
            });
        }
    }
}
