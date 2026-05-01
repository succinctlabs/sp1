use core::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};

use crate::{
    air::SP1CoreAirBuilder, memory::MemoryAccessCols, program::InstructionCols,
    utils::next_multiple_of_32,
};
use hashbrown::HashMap;
use itertools::Itertools;
use slop_air::{Air, AirBuilder, BaseAir};
use slop_algebra::{AbstractField, Field, PrimeField, PrimeField32};
use slop_matrix::Matrix;
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, InstructionFetchEvent, MemoryAccessPosition},
    ByteOpcode, ExecutionRecord, MemoryAccessRecord, Opcode, Program,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::MachineAir;
use sp1_primitives::consts::{u64_to_u16_limbs, PROT_EXEC, PROT_READ};

/// The number of program columns.
pub const NUM_INSTRUCTION_FETCH_COLS: usize = size_of::<InstructionFetchCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct InstructionFetchCols<T> {
    pub clk_high: T,
    pub clk_low: T,
    pub pc: [T; 3],
    /// This is used to check if the top two limbs of the `pc` is not both zero.
    pub top_two_limb_inv: T,

    pub instruction: InstructionCols<T>,
    pub instr_type: T,
    pub base_opcode: T,
    pub funct3: T,
    pub funct7: T,

    pub memory_access: MemoryAccessCols<T>,
    /// The selected 32 bits of read memory, in this case the 32 bit encoded instruction.
    pub selected_word: [T; 2],
    pub offset: T,
    pub is_real: T,
}

/// A chip that implements instruction fetching from memory.
#[derive(Default)]
pub struct InstructionFetchChip;

impl InstructionFetchChip {
    pub const fn new() -> Self {
        Self {}
    }

    fn event_to_row<F: PrimeField>(
        &self,
        event: &InstructionFetchEvent,
        memory_access: &MemoryAccessRecord,
        cols: &mut InstructionFetchCols<F>,
    ) {
        let instruction = event.instruction;
        let (mem_access, encoded) = memory_access.untrusted_instruction.unwrap();
        assert_eq!(encoded, event.encoded_instruction);

        let pc = event.pc; // input.program.pc_base + event.pc as u64 * 4;
        cols.pc = [
            F::from_canonical_u16((pc & 0xFFFF) as u16),
            F::from_canonical_u16(((pc >> 16) & 0xFFFF) as u16),
            F::from_canonical_u16(((pc >> 32) & 0xFFFF) as u16),
        ];

        let sum_top_two_limb = cols.pc[1] + cols.pc[2];
        cols.top_two_limb_inv = sum_top_two_limb.inverse();

        let clk_high = (event.clk >> 24) as u32;
        let clk_low = (event.clk & 0xFFFFFF) as u32;
        cols.clk_high = F::from_canonical_u32(clk_high);
        cols.clk_low = F::from_canonical_u32(clk_low);

        if instruction.opcode != Opcode::UNIMP {
            let (instr_type, instr_type_imm) = instruction.opcode.instruction_type();
            cols.instr_type = if instr_type_imm.is_some() && instruction.imm_c {
                F::from_canonical_u32(instr_type_imm.unwrap() as u32)
            } else {
                F::from_canonical_u32(instr_type as u32)
            };
            assert!(cols.instr_type != F::zero());

            let (base_opcode, base_imm_opcode) = instruction.opcode.base_opcode();
            cols.base_opcode = if base_imm_opcode.is_some() && instruction.imm_c {
                F::from_canonical_u32(base_imm_opcode.unwrap())
            } else {
                F::from_canonical_u32(base_opcode)
            };
            let funct3 = instruction.opcode.funct3().unwrap_or(0);
            let funct7 = instruction.opcode.funct7().unwrap_or(0);
            cols.funct3 = F::from_canonical_u8(funct3);
            cols.funct7 = F::from_canonical_u8(funct7);
        }

        // Offset indicates whether we want lower or upper 32 bits of the instruction
        let offset = (pc / 4) % 2;
        cols.offset = F::from_canonical_u8(offset as u8);

        // Turn into 4 16 bit limbs
        let limbs = u64_to_u16_limbs(mem_access.value());

        // Select based on the offset either the first two or last two limbs
        // Either 0 or 2
        let limb_selector = 2 * offset;

        // Note selected word is equivalent to the 32 bit encoded instruction
        cols.selected_word = [
            F::from_canonical_u16(limbs[limb_selector as usize]),
            F::from_canonical_u16(limbs[limb_selector as usize + 1]),
        ];

        let instruction = event.instruction;
        cols.instruction.populate(&instruction);

        // Check that the encoded instruction is correct
        let encoding_check = instruction.encode();
        assert_eq!(event.encoded_instruction, encoding_check);

        cols.is_real = F::one();
    }
}

impl<F: PrimeField32> MachineAir<F> for InstructionFetchChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        "InstructionFetch"
    }

    fn generate_dependencies(&self, input: &ExecutionRecord, output: &mut ExecutionRecord) {
        let mut blu_batches = Vec::new();
        for full_event in input.instruction_fetch_events.iter() {
            let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
            let mut row = [F::zero(); NUM_INSTRUCTION_FETCH_COLS];
            let cols: &mut InstructionFetchCols<F> = row.as_mut_slice().borrow_mut();
            let (event, memory_access) = full_event;
            let (mem_access, encoded) = memory_access.untrusted_instruction.unwrap();
            assert_eq!(encoded, event.encoded_instruction);
            cols.memory_access.populate(mem_access, &mut blu);
            let pc = event.pc;

            let pc_0 = (pc & 0xFFFF) as u16;
            let pc_1 = ((pc >> 16) & 0xFFFF) as u16;
            let pc_2 = ((pc >> 32) & 0xFFFF) as u16;
            blu.add_u16_range_checks(&[pc_0, pc_1, pc_2]);

            self.event_to_row(event, memory_access, cols);

            let offset: u16 = cols.offset.as_canonical_u32().try_into().unwrap();

            blu.add_bit_range_check((pc_0 - 4 * offset) / 8, 13);

            blu_batches.push(blu);
        }

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let padded_nb_rows =
            <InstructionFetchChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let num_event_rows = input.instruction_fetch_events.len();

        unsafe {
            let padding_start = num_event_rows * NUM_INSTRUCTION_FETCH_COLS;
            let padding_size = (padded_nb_rows - num_event_rows) * NUM_INSTRUCTION_FETCH_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe {
            core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * NUM_INSTRUCTION_FETCH_COLS)
        };

        let chunk_size = std::cmp::max(input.instruction_fetch_events.len() / num_cpus::get(), 1);

        values.chunks_mut(chunk_size * NUM_INSTRUCTION_FETCH_COLS).enumerate().for_each(
            |(i, rows)| {
                rows.chunks_mut(NUM_INSTRUCTION_FETCH_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut InstructionFetchCols<F> = row.borrow_mut();
                    let (event, memory_access) = &input.instruction_fetch_events[idx];

                    let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                    let (mem_access, encoded) = memory_access.untrusted_instruction.unwrap();
                    assert_eq!(encoded, event.encoded_instruction);
                    assert!(mem_access.current_record().timestamp == event.clk);

                    cols.memory_access.populate(mem_access, &mut blu);
                    self.event_to_row(event, memory_access, cols);
                });
            },
        );
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.instruction_fetch_events.is_empty()
        }
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = next_multiple_of_32(
            input.instruction_fetch_events.len(),
            input.fixed_log2_rows::<F, _>(self),
        );

        Some(nb_rows)
    }
}

impl<F> BaseAir<F> for InstructionFetchChip {
    fn width(&self) -> usize {
        NUM_INSTRUCTION_FETCH_COLS
    }
}

impl<AB> Air<AB> for InstructionFetchChip
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &InstructionFetchCols<AB::Var> = (*local).borrow();

        let clk_high = local.clk_high.into();
        let clk_low = local.clk_low.into();

        #[cfg(not(feature = "mprotect"))]
        builder.assert_zero(local.is_real);

        builder.assert_bool(local.is_real.into());
        builder.assert_eq(
            builder.extract_public_values().is_untrusted_programs_enabled,
            AB::Expr::one(),
        );

        // Verify and calculate aligned address
        builder.slice_range_check_u16(&local.pc, local.is_real);
        builder.assert_bool(local.offset);
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            (local.pc[0] - AB::Expr::from_canonical_u32(4) * local.offset)
                * AB::F::from_canonical_u32(8).inverse(),
            AB::Expr::from_canonical_u32(13),
            AB::Expr::zero(),
            local.is_real.into(),
        );
        let sum_top_two_limb = local.pc[1] + local.pc[2];

        // Check that `pc >= 2^16`, so it doesn't touch registers.
        // This implements a stack guard of size 2^16 bytes = 64KB.
        // If `is_real = 1`, then `pc[1] + pc[2] != 0`, so `pc >= 2^16`.
        builder.assert_eq(local.top_two_limb_inv * sum_top_two_limb, local.is_real);

        let aligned_addr: [AB::Expr; 3] = [
            local.pc[0] - AB::Expr::from_canonical_u32(4) * local.offset,
            local.pc[1].into(),
            local.pc[2].into(),
        ];

        // Verify picked correct instruction from address

        // Step 2. Read the memory address.
        builder.eval_memory_access_read(
            clk_high.clone(),
            clk_low.clone()
                + AB::Expr::from_canonical_u32(MemoryAccessPosition::UntrustedInstruction as u32),
            &aligned_addr,
            local.memory_access,
            local.is_real.into(),
        );

        builder
            .when_not(local.offset)
            .assert_eq(local.selected_word[0], local.memory_access.prev_value[0]);
        builder
            .when_not(local.offset)
            .assert_eq(local.selected_word[1], local.memory_access.prev_value[1]);
        builder
            .when(local.offset)
            .assert_eq(local.selected_word[0], local.memory_access.prev_value[2]);
        builder
            .when(local.offset)
            .assert_eq(local.selected_word[1], local.memory_access.prev_value[3]);

        // Constrain the interaction with untrusted program memory table
        let untrusted_instruction_const_fields = [
            local.instr_type.into(),
            local.base_opcode.into(),
            local.funct3.into(),
            local.funct7.into(),
        ];

        builder.receive_instruction_fetch(
            local.pc,
            local.instruction,
            untrusted_instruction_const_fields.clone(),
            [clk_high.clone(), clk_low.clone()],
            local.is_real.into(),
        );

        builder.send_instruction_decode(
            local.selected_word,
            local.instruction,
            untrusted_instruction_const_fields,
            local.is_real.into(),
        );

        builder.send_page_prot(
            clk_high,
            clk_low,
            &aligned_addr.map(Into::into),
            AB::Expr::from_canonical_u8(PROT_READ | PROT_EXEC),
            local.is_real.into(),
        );
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::print_stdout)]

    use std::sync::Arc;

    use sp1_primitives::SP1Field;

    use slop_matrix::dense::RowMajorMatrix;
    use sp1_core_executor::{ExecutionRecord, Instruction, Opcode, Program};
    use sp1_hypercube::air::MachineAir;

    use crate::program::InstructionFetchChip;

    #[test]
    fn generate_trace() {
        // main:
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     add x31, x30, x29
        let instructions = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADDI, 30, 0, 37, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
        ];
        let shard = ExecutionRecord {
            program: Arc::new(Program::new(instructions, 0, 0)),
            ..Default::default()
        };
        let chip = InstructionFetchChip::new();
        let trace: RowMajorMatrix<SP1Field> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }
}
