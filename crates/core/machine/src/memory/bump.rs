use std::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};

use crate::{air::SP1CoreAirBuilder, utils::next_multiple_of_32};

use super::MemoryAccessCols;
use hashbrown::HashMap;
use itertools::Itertools;
use slop_air::{Air, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, MemoryReadRecord, MemoryRecordEnum},
    ByteOpcode, ExecutionRecord, Program,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::MachineAir;
use struct_reflection::{StructReflection, StructReflectionHelper};

pub(crate) const NUM_MEMORY_BUMP_COLS: usize = size_of::<MemoryBumpCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, StructReflection)]
#[repr(C)]
pub struct MemoryBumpCols<T: Copy> {
    pub access: MemoryAccessCols<T>,
    pub clk_32_48: T,
    pub clk_24_32: T,
    pub clk_16_24: T,
    pub clk_0_16: T,
    pub addr: T,
    pub is_real: T,
}

pub struct MemoryBumpChip {}

impl MemoryBumpChip {
    pub const fn new() -> Self {
        Self {}
    }
}

impl<F> BaseAir<F> for MemoryBumpChip {
    fn width(&self) -> usize {
        NUM_MEMORY_BUMP_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for MemoryBumpChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        "MemoryBump"
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let chunk_size = 1;
        let event_iter = input.bump_memory_events.chunks(chunk_size);

        let blu_batches = event_iter
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|(event, addr, is_refresh)| {
                    let mut row = [F::zero(); NUM_MEMORY_BUMP_COLS];
                    let cols: &mut MemoryBumpCols<F> = row.as_mut_slice().borrow_mut();
                    let value = event.prev_value();
                    let prev_timestamp = event.previous_record().timestamp;
                    let mut timestamp = event.current_record().timestamp;
                    if !is_refresh {
                        timestamp = (timestamp >> 24) << 24;
                    }
                    let bump_event = MemoryRecordEnum::Read(MemoryReadRecord {
                        value,
                        prev_timestamp,
                        timestamp,
                        prev_page_prot_record: None,
                    });
                    cols.access.populate(bump_event, &mut blu);
                    blu.add_u16_range_checks(&[
                        (timestamp & 0xFFFF) as u16,
                        ((timestamp >> 32) & 0xFFFF) as u16,
                    ]);
                    blu.add_u8_range_checks(&[
                        ((timestamp >> 16) & 0xFF) as u8,
                        ((timestamp >> 24) & 0xFF) as u8,
                    ]);
                    blu.add_byte_lookup_event(ByteLookupEvent {
                        opcode: ByteOpcode::LTU,
                        a: 1,
                        b: *addr as u8,
                        c: 32,
                    });
                    cols.is_real = F::one();
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = input.bump_memory_events.len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        Some(next_multiple_of_32(nb_rows, size_log2))
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let chunk_size = 1;
        let padded_nb_rows = <MemoryBumpChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let num_event_rows = input.bump_memory_events.len();

        unsafe {
            let padding_start = num_event_rows * NUM_MEMORY_BUMP_COLS;
            let padding_size = (padded_nb_rows - num_event_rows) * NUM_MEMORY_BUMP_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe {
            core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * NUM_MEMORY_BUMP_COLS)
        };

        values.chunks_mut(chunk_size * NUM_MEMORY_BUMP_COLS).enumerate().for_each(|(i, rows)| {
            rows.chunks_mut(NUM_MEMORY_BUMP_COLS).enumerate().for_each(|(j, row)| {
                let idx = i * chunk_size + j;
                let cols: &mut MemoryBumpCols<F> = row.borrow_mut();

                if idx < input.bump_memory_events.len() {
                    let mut byte_lookup_events = Vec::new();
                    let (event, addr, is_refresh) = input.bump_memory_events[idx];
                    let value = event.prev_value();
                    let prev_timestamp = event.previous_record().timestamp;
                    let mut timestamp = event.current_record().timestamp;
                    if !is_refresh {
                        timestamp = (timestamp >> 24) << 24;
                    }
                    let bump_event = MemoryRecordEnum::Read(MemoryReadRecord {
                        value,
                        prev_timestamp,
                        timestamp,
                        prev_page_prot_record: None,
                    });
                    cols.access.populate(bump_event, &mut byte_lookup_events);
                    cols.clk_0_16 = F::from_canonical_u16((timestamp & 0xFFFF) as u16);
                    cols.clk_16_24 = F::from_canonical_u8(((timestamp >> 16) & 0xFF) as u8);
                    cols.clk_24_32 = F::from_canonical_u8(((timestamp >> 24) & 0xFF) as u8);
                    cols.clk_32_48 = F::from_canonical_u16(((timestamp >> 32) & 0xFFFF) as u16);
                    cols.addr = F::from_canonical_u64(addr);
                    cols.is_real = F::one();
                }
            })
        });
    }

    fn included(&self, shard: &Self::Record) -> bool {
        shard.cpu_event_count != 0
    }

    fn column_names(&self) -> Vec<String> {
        MemoryBumpCols::<F>::struct_reflection().unwrap()
    }
}

impl<AB> Air<AB> for MemoryBumpChip
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MemoryBumpCols<AB::Var> = (*local).borrow();

        // Check that `is_real` is a boolean value.
        builder.assert_bool(local.is_real);

        // Check that the timestamp limbs are within range.
        builder.slice_range_check_u16(&[local.clk_0_16, local.clk_32_48], local.is_real);
        builder.slice_range_check_u8(&[local.clk_16_24, local.clk_24_32], local.is_real);

        // Check that the address is a valid register.
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::LTU as u32),
            AB::Expr::one(),
            local.addr,
            AB::Expr::from_canonical_u8(32),
            local.is_real,
        );

        // Bump the memory timestamp by doing an additional read.
        builder.eval_memory_access_read(
            local.clk_24_32 + local.clk_32_48 * AB::Expr::from_canonical_u32(1 << 8),
            local.clk_0_16 + local.clk_16_24 * AB::Expr::from_canonical_u32(1 << 16),
            &[local.addr.into(), AB::Expr::zero(), AB::Expr::zero()],
            local.access,
            local.is_real,
        );
    }
}
