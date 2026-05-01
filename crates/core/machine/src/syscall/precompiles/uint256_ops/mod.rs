mod air;

use num::{BigUint, One, Zero};
use slop_air::BaseAir;
use slop_algebra::PrimeField32;
use sp1_core_executor::{
    events::{ByteRecord, MemoryRecordEnum, PrecompileEvent},
    ExecutionRecord, Program, SyscallCode,
};
use sp1_curves::{params::NumWords, uint256::U256Field};
use sp1_hypercube::air::MachineAir;
use sp1_primitives::consts::{PROT_READ, PROT_WRITE};
use std::{borrow::BorrowMut, mem::MaybeUninit};

use crate::memory::{MemoryAccessCols, MemoryAccessColsU8};

pub use air::{
    num_uint256_ops_cols_supervisor, num_uint256_ops_cols_user, Uint256OpsChip, Uint256OpsCols,
};
use typenum::Unsigned;
type WordsFieldElement = <U256Field as NumWords>::WordsFieldElement;
const WORDS_FIELD_ELEMENT: usize = WordsFieldElement::USIZE;

use crate::{utils::next_multiple_of_32, TrustMode, UserMode};

pub const U256_NUM_WORDS: usize = 4;

impl<F: PrimeField32, M: TrustMode> MachineAir<F> for Uint256OpsChip<M> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        if M::IS_TRUSTED {
            "Uint256Ops"
        } else {
            "Uint256OpsUser"
        }
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return Some(0);
        }
        let nb_rows = input.get_precompile_events(SyscallCode::UINT256_ADD_CARRY).len()
            + input.get_precompile_events(SyscallCode::UINT256_MUL_CARRY).len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_multiple_of_32(nb_rows, size_log2);
        Some(padded_nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return;
        }

        let width = <Uint256OpsChip<M> as BaseAir<F>>::width(self);
        let padded_nb_rows = <Uint256OpsChip<M> as MachineAir<F>>::num_rows(self, input).unwrap();
        let mut events = Vec::new();
        events.extend(input.get_precompile_events(SyscallCode::UINT256_ADD_CARRY).iter());
        events.extend(input.get_precompile_events(SyscallCode::UINT256_MUL_CARRY).iter());
        let num_event_rows = events.len();
        let chunk_size = 1;

        unsafe {
            let padding_start = num_event_rows * width;
            let padding_size = (padded_nb_rows - num_event_rows) * width;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let buffer_as_slice =
            unsafe { core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * width) };

        let mut new_byte_lookup_events = Vec::new();

        buffer_as_slice.chunks_mut(chunk_size * width).enumerate().for_each(|(i, rows)| {
            rows.chunks_mut(width).enumerate().for_each(|(j, row)| {
                let idx = i * chunk_size + j;
                if idx < events.len() {
                    let event = &events[idx].1;
                    let event = if let PrecompileEvent::Uint256Ops(event) = event {
                        event
                    } else {
                        unreachable!()
                    };
                    let cols: &mut Uint256OpsCols<F, M> = row.borrow_mut();

                    // Set is_real flag
                    cols.is_real = F::one();

                    // Populate clk fields
                    cols.clk_high = F::from_canonical_u32((event.clk >> 24) as u32);
                    cols.clk_low = F::from_canonical_u32((event.clk & 0xFFFFFF) as u32);

                    // Populate address operations
                    cols.a_ptr.populate(&mut new_byte_lookup_events, event.a_ptr, 32);
                    cols.b_ptr.populate(&mut new_byte_lookup_events, event.b_ptr, 32);
                    cols.c_ptr.populate(&mut new_byte_lookup_events, event.c_ptr, 32);
                    cols.d_ptr.populate(&mut new_byte_lookup_events, event.d_ptr, 32);
                    cols.e_ptr.populate(&mut new_byte_lookup_events, event.e_ptr, 32);

                    // Populate memory accesses for pointer reads
                    let c_ptr_memory_record = MemoryRecordEnum::Read(event.c_ptr_memory);
                    let d_ptr_memory_record = MemoryRecordEnum::Read(event.d_ptr_memory);
                    let e_ptr_memory_record = MemoryRecordEnum::Read(event.e_ptr_memory);
                    cols.c_ptr_memory.populate(c_ptr_memory_record, &mut new_byte_lookup_events);
                    cols.d_ptr_memory.populate(d_ptr_memory_record, &mut new_byte_lookup_events);
                    cols.e_ptr_memory.populate(e_ptr_memory_record, &mut new_byte_lookup_events);

                    let mut is_not_trap = true;
                    let mut trap_code = 0u8;

                    if !M::IS_TRUSTED {
                        let cols: &mut Uint256OpsCols<F, UserMode> = row.borrow_mut();
                        // Populate page protection operations (once per event, not per word)
                        cols.address_slice_page_prot_access_a.populate(
                            &mut new_byte_lookup_events,
                            event.a_ptr,
                            event.a_ptr + ((WORDS_FIELD_ELEMENT - 1) * 8) as u64,
                            event.clk,
                            PROT_READ,
                            &event.page_prot_records.read_a_page_prot_records,
                            &mut is_not_trap,
                            &mut trap_code,
                        );

                        cols.address_slice_page_prot_access_b.populate(
                            &mut new_byte_lookup_events,
                            event.b_ptr,
                            event.b_ptr + ((WORDS_FIELD_ELEMENT - 1) * 8) as u64,
                            event.clk + 1,
                            PROT_READ,
                            &event.page_prot_records.read_b_page_prot_records,
                            &mut is_not_trap,
                            &mut trap_code,
                        );

                        cols.address_slice_page_prot_access_c.populate(
                            &mut new_byte_lookup_events,
                            event.c_ptr,
                            event.c_ptr + ((WORDS_FIELD_ELEMENT - 1) * 8) as u64,
                            event.clk + 2,
                            PROT_READ,
                            &event.page_prot_records.read_c_page_prot_records,
                            &mut is_not_trap,
                            &mut trap_code,
                        );

                        cols.address_slice_page_prot_access_d.populate(
                            &mut new_byte_lookup_events,
                            event.d_ptr,
                            event.d_ptr + ((WORDS_FIELD_ELEMENT - 1) * 8) as u64,
                            event.clk + 3,
                            PROT_WRITE,
                            &event.page_prot_records.write_d_page_prot_records,
                            &mut is_not_trap,
                            &mut trap_code,
                        );

                        cols.address_slice_page_prot_access_e.populate(
                            &mut new_byte_lookup_events,
                            event.e_ptr,
                            event.e_ptr + ((WORDS_FIELD_ELEMENT - 1) * 8) as u64,
                            event.clk + 4,
                            PROT_WRITE,
                            &event.page_prot_records.write_e_page_prot_records,
                            &mut is_not_trap,
                            &mut trap_code,
                        );
                    }

                    let cols: &mut Uint256OpsCols<F, M> = row.borrow_mut();

                    // Populate memory accesses for value reads/writes
                    for i in 0..WORDS_FIELD_ELEMENT {
                        cols.a_addrs[i].populate(
                            &mut new_byte_lookup_events,
                            event.a_ptr,
                            8 * i as u64,
                        );
                        cols.b_addrs[i].populate(
                            &mut new_byte_lookup_events,
                            event.b_ptr,
                            8 * i as u64,
                        );
                        cols.c_addrs[i].populate(
                            &mut new_byte_lookup_events,
                            event.c_ptr,
                            8 * i as u64,
                        );
                        cols.d_addrs[i].populate(
                            &mut new_byte_lookup_events,
                            event.d_ptr,
                            8 * i as u64,
                        );
                        cols.e_addrs[i].populate(
                            &mut new_byte_lookup_events,
                            event.e_ptr,
                            8 * i as u64,
                        );

                        if is_not_trap {
                            let a_record = MemoryRecordEnum::Read(event.a_memory_records[i]);
                            let b_record = MemoryRecordEnum::Read(event.b_memory_records[i]);
                            let c_record = MemoryRecordEnum::Read(event.c_memory_records[i]);
                            let d_record = MemoryRecordEnum::Write(event.d_memory_records[i]);
                            let e_record = MemoryRecordEnum::Write(event.e_memory_records[i]);
                            cols.a_memory[i].populate(a_record, &mut new_byte_lookup_events);
                            cols.b_memory[i].populate(b_record, &mut new_byte_lookup_events);
                            cols.c_memory[i].populate(c_record, &mut new_byte_lookup_events);
                            cols.d_memory[i].populate(d_record, &mut new_byte_lookup_events);
                            cols.e_memory[i].populate(e_record, &mut new_byte_lookup_events);
                        } else {
                            cols.a_memory[i] = MemoryAccessColsU8::default();
                            cols.b_memory[i] = MemoryAccessColsU8::default();
                            cols.c_memory[i] = MemoryAccessColsU8::default();
                            cols.d_memory[i] = MemoryAccessCols::default();
                            cols.e_memory[i] = MemoryAccessCols::default();
                        }
                    }

                    // Set operation flags
                    match event.op {
                        sp1_core_executor::events::Uint256Operation::Add => {
                            cols.is_add = F::one();
                            cols.is_mul = F::zero();
                        }
                        sp1_core_executor::events::Uint256Operation::Mul => {
                            cols.is_add = F::zero();
                            cols.is_mul = F::one();
                        }
                    }

                    // Convert values to BigUint for field operations
                    let a = BigUint::from_slice(
                        &event
                            .a
                            .iter()
                            .flat_map(|&x| [x as u32, (x >> 32) as u32])
                            .collect::<Vec<_>>(),
                    );
                    let b = BigUint::from_slice(
                        &event
                            .b
                            .iter()
                            .flat_map(|&x| [x as u32, (x >> 32) as u32])
                            .collect::<Vec<_>>(),
                    );
                    let c = BigUint::from_slice(
                        &event
                            .c
                            .iter()
                            .flat_map(|&x| [x as u32, (x >> 32) as u32])
                            .collect::<Vec<_>>(),
                    );

                    // Populate field operation based on operation type
                    let is_add =
                        matches!(event.op, sp1_core_executor::events::Uint256Operation::Add);
                    let is_mul =
                        matches!(event.op, sp1_core_executor::events::Uint256Operation::Mul);
                    let modulus = BigUint::one() << 256;

                    cols.field_op.populate_conditional_op_and_carry(
                        &mut new_byte_lookup_events,
                        &a,
                        &b,
                        &c,
                        &modulus,
                        is_add,
                        is_mul,
                    );
                }
            })
        });

        for row in num_event_rows..padded_nb_rows {
            let row_start = row * width;
            let row = unsafe {
                core::slice::from_raw_parts_mut(buffer[row_start..].as_mut_ptr() as *mut F, width)
            };
            let cols: &mut Uint256OpsCols<F, M> = row.borrow_mut();

            let zero = BigUint::zero();
            cols.field_op.populate_conditional_op_and_carry(
                &mut vec![],
                &zero,
                &zero,
                &zero,
                &(BigUint::one() << 256),
                true,
                false,
            );
        }

        output.add_byte_lookup_events(new_byte_lookup_events);
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if M::IS_TRUSTED == shard.program.enable_untrusted_programs {
            return false;
        }

        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::UINT256_ADD_CARRY).is_empty()
                || !shard.get_precompile_events(SyscallCode::UINT256_MUL_CARRY).is_empty()
        }
    }
}
