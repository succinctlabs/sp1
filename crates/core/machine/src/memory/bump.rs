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

pub const NUM_MEMORY_BUMP_COLS: usize = size_of::<MemoryBumpCols<u8>>();

#[derive(AlignedBorrow, Default, Clone, Copy, StructReflection)]
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

// Witgen in an unconstrained `impl` (column type is the builder's `Field`).
impl<T: Copy> MemoryBumpCols<T> {
    /// Backend-agnostic witgen for the `MemoryBump` chip: the bump timestamp is the
    /// raw access timestamp on refresh rows, else its top-40-bit truncation
    /// (`(ts >> 24) << 24`); the row is a synthetic memory READ at that timestamp
    /// (composing [`MemoryAccessCols::witgen`]), plus the timestamp limb splits, the
    /// register address, and the dependency lookups (u16/u8 limb checks + the
    /// `addr < 32` LTU byte lookup) — mirrors `generate_dependencies` exactly.
    pub fn witgen<WB: crate::air::WitnessBuilder>(
        wb: &mut WB,
        cols: &mut MemoryBumpCols<WB::Field>,
        prev_value: WB::Nat,
        prev_timestamp: WB::Nat,
        raw_timestamp: WB::Nat,
        is_refresh: WB::Nat,
        addr: WB::Nat,
    ) {
        let c24 = wb.const_nat(24);
        let ts_hi = wb.shr(raw_timestamp, c24);
        let ts_masked = wb.shl(ts_hi, c24);
        let timestamp = wb.select(is_refresh, raw_timestamp, ts_masked);

        MemoryAccessCols::<WB::Field>::witgen(
            wb,
            &mut cols.access,
            prev_value,
            prev_timestamp,
            timestamp,
        );

        let t0 = wb.bits(timestamp, 0, 16);
        cols.clk_0_16 = wb.nat_to_field(t0);
        let t16 = wb.bits(timestamp, 16, 8);
        cols.clk_16_24 = wb.nat_to_field(t16);
        let t24 = wb.bits(timestamp, 24, 8);
        cols.clk_24_32 = wb.nat_to_field(t24);
        let t32 = wb.bits(timestamp, 32, 16);
        cols.clk_32_48 = wb.nat_to_field(t32);
        cols.addr = wb.nat_to_field(addr);
        let one = wb.const_nat(1);
        cols.is_real = wb.nat_to_field(one);

        // Dependency lookups (generate_dependencies).
        wb.add_u16_range_check(t0);
        wb.add_u16_range_check(t32);
        wb.add_u8_range_check(t16, t24);
        let ltu = wb.const_nat(ByteOpcode::LTU as u64);
        let c32 = wb.const_nat(32);
        wb.add_byte_lookup(ltu, one, addr, c32);
    }
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
