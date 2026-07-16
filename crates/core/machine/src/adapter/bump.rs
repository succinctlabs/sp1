use std::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};

use crate::{air::SP1CoreAirBuilder, utils::next_multiple_of_32};
use hashbrown::HashMap;
use itertools::Itertools;
use slop_air::{Air, AirBuilder, BaseAir};
use slop_algebra::{AbstractField, Field, PrimeField32};
use slop_matrix::Matrix;
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ByteOpcode, ExecutionRecord, Program, PC_INC,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::MachineAir;
use struct_reflection::{StructReflection, StructReflectionHelper};
pub const NUM_STATE_BUMP_COLS: usize = size_of::<StateBumpCols<u8>>();

#[derive(AlignedBorrow, Default, Clone, Copy, StructReflection)]
#[repr(C)]
pub struct StateBumpCols<T: Copy> {
    pub next_clk_32_48: T,
    pub next_clk_24_32: T,
    pub next_clk_16_24: T,
    pub next_clk_0_16: T,
    pub clk_high: T,
    pub clk_low: T,
    pub next_pc: [T; 3],
    pub pc: [T; 3],
    pub is_clk: T,
    pub is_real: T,
}

/// Witgen inputs for the `StateBump` chip: one `#[repr(C)]` row per event. The GPU
/// packs each event into one `StateBumpWitgenInput<u64>` and the op-DAG recorder
/// casts a wire slice to the same struct (see `record_witgen_inputs`), so field
/// order IS the kernel input layout.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct StateBumpWitgenInput<T> {
    pub clk: T,
    pub increment: T,
    /// Whether the received pc is the un-carried `prev_pc + PC_INC` form (0/1).
    pub bump2: T,
    pub pc: T,
}

/// Number of witgen inputs per `StateBump` row.
pub const NUM_STATE_BUMP_WITGEN_INPUTS: usize = size_of::<StateBumpWitgenInput<u8>>();

// Witgen in an unconstrained `impl` (column type is the builder's `Field`).
impl<T: Copy> StateBumpCols<T> {
    /// Backend-agnostic witgen for the `StateBump` chip: next_clk = clk + increment
    /// decomposed into 16/8/8/16 limbs, `clk_low = (clk & 0xFFFFFF) + increment`
    /// (possibly non-canonical), the pc/next_pc u16 limbs (with the `bump2` carry
    /// correction on the low limb), the 24-bit carry flag `is_clk`, and the
    /// dependency range checks (mirrors `generate_dependencies`).
    pub fn witgen<WB: crate::air::WitnessBuilder>(
        wb: &mut WB,
        cols: &mut StateBumpCols<WB::Field>,
        input: &StateBumpWitgenInput<WB::Nat>,
    ) {
        let StateBumpWitgenInput { clk, increment, bump2, pc } = *input;
        let one = wb.const_nat(1);
        let zero = wb.const_nat(0);

        // clk_low = (clk & 0xFFFFFF) + increment (may exceed 24 bits — sent as-is).
        let clk_0_24 = wb.bits(clk, 0, 24);
        let clk_low = wb.wrapping_add(clk_0_24, increment);
        cols.clk_low = wb.nat_to_field(clk_low);
        let clk_high = wb.bits(clk, 24, 32);
        cols.clk_high = wb.nat_to_field(clk_high);

        // next_clk limbs (canonical form).
        let next_clk = wb.wrapping_add(clk, increment);
        let n0 = wb.bits(next_clk, 0, 16);
        cols.next_clk_0_16 = wb.nat_to_field(n0);
        let n16 = wb.bits(next_clk, 16, 8);
        cols.next_clk_16_24 = wb.nat_to_field(n16);
        let n24 = wb.bits(next_clk, 24, 8);
        cols.next_clk_24_32 = wb.nat_to_field(n24);
        let n32 = wb.bits(next_clk, 32, 16);
        cols.next_clk_32_48 = wb.nat_to_field(n32);

        // next_pc = the event pc in u16 limbs (canonical).
        let pc0 = wb.bits(pc, 0, 16);
        let pc1 = wb.bits(pc, 16, 16);
        let pc2 = wb.bits(pc, 32, 16);
        cols.next_pc[0] = wb.nat_to_field(pc0);
        cols.next_pc[1] = wb.nat_to_field(pc1);
        cols.next_pc[2] = wb.nat_to_field(pc2);

        // pc: on `bump2` rows the received pc is the un-carried form
        // `prev_pc + PC_INC` on the low limb (prev_pc = pc - PC_INC); otherwise the
        // received pc equals next_pc.
        let pc_inc = wb.const_nat(PC_INC as u64);
        let prev_pc = wb.wrapping_sub(pc, pc_inc);
        let pp0 = wb.bits(prev_pc, 0, 16);
        let pp0_inc = wb.wrapping_add(pp0, pc_inc);
        let pp1 = wb.bits(prev_pc, 16, 16);
        let pp2 = wb.bits(prev_pc, 32, 16);
        let s0 = wb.select(bump2, pp0_inc, pc0);
        let s1 = wb.select(bump2, pp1, pc1);
        let s2 = wb.select(bump2, pp2, pc2);
        cols.pc[0] = wb.nat_to_field(s0);
        cols.pc[1] = wb.nat_to_field(s1);
        cols.pc[2] = wb.nat_to_field(s2);

        // is_clk = (next_clk >> 24) != (clk >> 24) — the low-24-bit carry happened.
        let next_hi = wb.bits(next_clk, 24, 40);
        let cur_hi = wb.bits(clk, 24, 40);
        let hi_eq = wb.eq(next_hi, cur_hi);
        let is_clk = wb.eq(hi_eq, zero);
        cols.is_clk = wb.nat_to_field(is_clk);
        cols.is_real = wb.nat_to_field(one);

        // Dependency lookups (generate_dependencies): clk canonicity + pc u16 limbs.
        let nm1 = wb.wrapping_sub(n0, one);
        let nm1_div8 = wb.bits(nm1, 3, 13);
        wb.add_bit_range_check(nm1_div8, 13);
        wb.add_bit_range_check(n32, 16);
        wb.add_u8_range_check(n16, n24);
        wb.add_u16_range_check(pc0);
        wb.add_u16_range_check(pc1);
        wb.add_u16_range_check(pc2);
    }
}

pub struct StateBumpChip {}

impl StateBumpChip {
    pub const fn new() -> Self {
        Self {}
    }
}

impl<F> BaseAir<F> for StateBumpChip {
    fn width(&self) -> usize {
        NUM_STATE_BUMP_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for StateBumpChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        "StateBump"
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let chunk_size = 1;
        let event_iter = input.bump_state_events.chunks(chunk_size);

        let blu_batches = event_iter
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|(clk, increment, _, pc)| {
                    let next_clk = clk + increment;
                    let next_clk_0_16 = (next_clk & 0xFFFF) as u16;
                    let next_clk_16_24 = ((next_clk >> 16) & 0xFF) as u8;
                    let next_clk_24_32 = ((next_clk >> 24) & 0xFF) as u8;
                    let next_clk_32_48 = (next_clk >> 32) as u16;
                    let pc_0 = (pc & 0xFFFF) as u16;
                    let pc_1 = ((pc >> 16) & 0xFFFF) as u16;
                    let pc_2 = ((pc >> 32) & 0xFFFF) as u16;

                    blu.add_bit_range_check((next_clk_0_16 - 1) / 8, 13);
                    blu.add_bit_range_check(next_clk_32_48, 16);
                    blu.add_u8_range_checks(&[next_clk_16_24, next_clk_24_32]);
                    blu.add_u16_range_checks(&[pc_0, pc_1, pc_2]);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = input.bump_state_events.len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        Some(next_multiple_of_32(nb_rows, size_log2))
    }

    fn generate_trace_into(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let chunk_size = 1;
        let padded_nb_rows = <StateBumpChip as MachineAir<F>>::num_rows(self, input).unwrap();

        let num_event_rows = input.bump_state_events.len();

        unsafe {
            let padding_start = num_event_rows * NUM_STATE_BUMP_COLS;
            let padding_size = (padded_nb_rows - num_event_rows) * NUM_STATE_BUMP_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe {
            core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * NUM_STATE_BUMP_COLS)
        };

        values.chunks_mut(chunk_size * NUM_STATE_BUMP_COLS).enumerate().for_each(|(i, rows)| {
            rows.chunks_mut(NUM_STATE_BUMP_COLS).enumerate().for_each(|(j, row)| {
                let idx = i * chunk_size + j;
                let cols: &mut StateBumpCols<F> = row.borrow_mut();

                if idx < input.bump_state_events.len() {
                    let (clk, increment, bump2, pc) = input.bump_state_events[idx];

                    let clk_low = ((clk & 0xFFFFFF) + increment) as u32;
                    let clk_high = (clk >> 24) as u32;
                    let next_clk = clk + increment;
                    let next_clk_0_16 = (next_clk & 0xFFFF) as u16;
                    let next_clk_16_24 = ((next_clk >> 16) & 0xFF) as u8;
                    let next_clk_24_32 = ((next_clk >> 24) & 0xFF) as u8;
                    let next_clk_32_48 = (next_clk >> 32) as u16;

                    cols.clk_low = F::from_canonical_u32(clk_low);
                    cols.clk_high = F::from_canonical_u32(clk_high);
                    cols.next_clk_0_16 = F::from_canonical_u16(next_clk_0_16);
                    cols.next_clk_16_24 = F::from_canonical_u8(next_clk_16_24);
                    cols.next_clk_24_32 = F::from_canonical_u8(next_clk_24_32);
                    cols.next_clk_32_48 = F::from_canonical_u16(next_clk_32_48);

                    cols.next_pc = [
                        F::from_canonical_u16((pc & 0xFFFF) as u16),
                        F::from_canonical_u16(((pc >> 16) & 0xFFFF) as u16),
                        F::from_canonical_u16(((pc >> 32) & 0xFFFF) as u16),
                    ];

                    if bump2 {
                        // All the instructions that require the StateBumpChip to correct the `pc`
                        // to its correct form increments the `pc` by the default `PC_INC`.
                        let prev_pc = pc.wrapping_sub(PC_INC as u64);
                        cols.pc = [
                            F::from_canonical_u16((prev_pc & 0xFFFF) as u16)
                                + F::from_canonical_u16(PC_INC as u16),
                            F::from_canonical_u16(((prev_pc >> 16) & 0xFFFF) as u16),
                            F::from_canonical_u16(((prev_pc >> 32) & 0xFFFF) as u16),
                        ];
                    } else {
                        cols.pc = cols.next_pc;
                    }

                    if (next_clk >> 24) != (clk >> 24) {
                        cols.is_clk = F::one();
                    } else {
                        cols.is_clk = F::zero();
                    }
                    cols.is_real = F::one();
                }
            });
        });
    }

    fn included(&self, shard: &Self::Record) -> bool {
        shard.cpu_event_count != 0
    }

    fn column_names(&self) -> Vec<String> {
        StateBumpCols::<F>::struct_reflection().unwrap()
    }
}

impl<AB> Air<AB> for StateBumpChip
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &StateBumpCols<AB::Var> = (*local).borrow();
        // Check that `is_real` is a boolean value.
        builder.assert_bool(local.is_real);

        // Receive the state with values potentially in non-canonical forms.
        builder.receive_state(local.clk_high, local.clk_low, local.pc, local.is_real);
        // Send the state with `clk_high, clk_low, next_pc` being in canonical forms.
        builder.send_state(
            local.next_clk_24_32 + local.next_clk_32_48 * AB::F::from_canonical_u32(1 << 8),
            local.next_clk_0_16 + local.next_clk_16_24 * AB::F::from_canonical_u32(1 << 16),
            local.next_pc,
            local.is_real,
        );

        // Check that the sent state's clk is in canonical form.
        // The bottom 16 bits of the `clk` is a u16 value that is 1 (mod 8).
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            (local.next_clk_0_16 - AB::Expr::one()) * AB::F::from_canonical_u8(8).inverse(),
            AB::Expr::from_canonical_u32(13),
            AB::Expr::zero(),
            local.is_real,
        );
        // The top 16 bits of the `clk` is a u16 value.
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            local.next_clk_32_48.into(),
            AB::Expr::from_canonical_u32(16),
            AB::Expr::zero(),
            local.is_real,
        );
        // The two 8 bit limbs in the middle of the clk are valid u8 values.
        builder.slice_range_check_u8(&[local.next_clk_16_24, local.next_clk_24_32], local.is_real);

        // If `is_clk` is true, a carry happens from the bottom 24 bit limb to the top.
        // First, check that `is_clk` is a boolean value. This is possible because the `clk` does
        // not increment by more than `2^24` in a single instruction cycle.
        builder.assert_bool(local.is_clk);
        builder.when(local.is_real).assert_eq(
            local.next_clk_24_32 + local.next_clk_32_48 * AB::F::from_canonical_u32(1 << 8),
            local.clk_high + local.is_clk,
        );
        builder.when(local.is_real).assert_eq(
            local.next_clk_0_16
                + local.next_clk_16_24 * AB::F::from_canonical_u32(1 << 16)
                + local.is_clk * AB::F::from_canonical_u32(1 << 24),
            local.clk_low,
        );

        // The `next_pc` is the `pc` with propagated carries.
        // The `next_pc` is checked to be canonical, three u16 limbs.
        let mut carry = AB::Expr::zero();
        for i in 0..3 {
            carry = (carry.clone() + local.pc[i] - local.next_pc[i])
                * AB::F::from_canonical_u32(1 << 16).inverse();
            builder.assert_bool(carry.clone());
        }
        builder.assert_zero(carry);
        builder.slice_range_check_u16(&local.next_pc, local.is_real);
    }
}
