use slop_algebra::PrimeField32;
use sp1_core_executor::events::{ByteRecord, MemoryRecordEnum, PageProtRecord};
use sp1_derive::AlignedBorrow;
use sp1_primitives::consts::WORD_SIZE;

use super::{
    MemoryAccessCols, MemoryAccessColsU8, MemoryAccessTimestamp, PageProtAccessCols,
    RegisterAccessCols, RegisterAccessTimestamp,
};

/// Witgen inputs of one memory/register access ([`RegisterAccessCols::witgen`] and
/// [`MemoryAccessCols::witgen`] operands), for nesting inside chip-level witgen-input
/// structs (see `record_witgen_inputs`).
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryAccessWitgenInput<T> {
    pub prev_value: T,
    pub prev_ts: T,
    pub cur_ts: T,
}

impl MemoryAccessWitgenInput<u64> {
    /// Pack an executor memory-access record into witgen-input form.
    pub fn from_record(record: MemoryRecordEnum) -> Self {
        Self {
            prev_value: record.previous_record().value,
            prev_ts: record.previous_record().timestamp,
            cur_ts: record.current_record().timestamp,
        }
    }
}

// Witgen in an unconstrained `impl<T>` (column type is the builder's `Field`).
impl<T> MemoryAccessCols<T> {
    /// Backend-agnostic witgen dual of [`Self::populate`]: the previous value (4 u16
    /// limbs) and the access timestamp (composing [`MemoryAccessTimestamp::witgen`]).
    pub fn witgen<WB: crate::air::WitnessBuilder>(
        wb: &mut WB,
        cols: &mut MemoryAccessCols<WB::Field>,
        prev_value: WB::Nat,
        prev_timestamp: WB::Nat,
        current_timestamp: WB::Nat,
    ) {
        for i in 0..WORD_SIZE {
            let limb = wb.bits(prev_value, (i as u32) * 16, 16);
            cols.prev_value[i] = wb.nat_to_field(limb);
        }
        MemoryAccessTimestamp::<WB::Field>::witgen(
            wb,
            &mut cols.access_timestamp,
            prev_timestamp,
            current_timestamp,
        );
    }
}

impl<F: PrimeField32> MemoryAccessCols<F> {
    pub fn populate(&mut self, record: MemoryRecordEnum, output: &mut impl ByteRecord) {
        let prev_record = record.previous_record();
        let current_record = record.current_record();
        // The witgen body computes `diff - 1` with wrapping ops (out-of-contract
        // inputs produce a garbage witness, not a panic), so keep the executor
        // invariant loud here like `MemoryAccessTimestamp::populate_timestamp` does —
        // an executor bug must fail at the access site, not as a far-away
        // verification error.
        assert!(
            prev_record.timestamp < current_record.timestamp,
            "prev_timestamp: {}, current_timestamp: {}",
            prev_record.timestamp,
            current_record.timestamp
        );
        let mut wb = crate::air::HostWitnessBuilder::<F, _>::new(output);
        Self::witgen(
            &mut wb,
            self,
            prev_record.value,
            prev_record.timestamp,
            current_record.timestamp,
        );
    }
}

// Witgen in an unconstrained `impl<T>` (column type is the builder's `Field`).
impl<T> RegisterAccessCols<T> {
    /// Backend-agnostic witgen: the previous value (4 u16 limbs) and the access
    /// timestamp (composing [`RegisterAccessTimestamp::witgen`]).
    pub fn witgen<WB: crate::air::WitnessBuilder>(
        wb: &mut WB,
        cols: &mut RegisterAccessCols<WB::Field>,
        prev_value: WB::Nat,
        prev_timestamp: WB::Nat,
        current_timestamp: WB::Nat,
    ) {
        for i in 0..WORD_SIZE {
            let limb = wb.bits(prev_value, (i as u32) * 16, 16);
            cols.prev_value[i] = wb.nat_to_field(limb);
        }
        RegisterAccessTimestamp::<WB::Field>::witgen(
            wb,
            &mut cols.access_timestamp,
            prev_timestamp,
            current_timestamp,
        );
    }
}

impl<F: PrimeField32> RegisterAccessCols<F> {
    pub fn populate(&mut self, record: MemoryRecordEnum, output: &mut impl ByteRecord) {
        let prev_record = record.previous_record();
        let current_record = record.current_record();
        let mut wb = crate::air::HostWitnessBuilder::<F, _>::new(output);
        Self::witgen(
            &mut wb,
            self,
            prev_record.value,
            prev_record.timestamp,
            current_record.timestamp,
        );
    }
}

impl<F: PrimeField32> MemoryAccessColsU8<F> {
    pub fn populate(&mut self, record: MemoryRecordEnum, output: &mut impl ByteRecord) {
        let prev_record = record.previous_record();
        let current_record = record.current_record();
        self.memory_access.prev_value = prev_record.value.into();
        self.prev_value_u8.populate_u16_to_u8_safe(output, prev_record.value);
        self.memory_access.access_timestamp.populate_timestamp(
            prev_record.timestamp,
            current_record.timestamp,
            output,
        );
    }
}

impl<F: PrimeField32> PageProtAccessCols<F> {
    pub fn populate(
        &mut self,
        prev_page_prot: &PageProtRecord,
        current_timestamp: u64,
        output: &mut impl ByteRecord,
    ) {
        self.prev_prot_bitmap = F::from_canonical_u8(prev_page_prot.page_prot);
        self.access_timestamp.populate_timestamp(
            prev_page_prot.timestamp,
            current_timestamp,
            output,
        );
    }
}

// Witgen in an unconstrained `impl<T>` (column type is the builder's `Field`).
impl<T> MemoryAccessTimestamp<T> {
    /// Backend-agnostic witgen dual of [`Self::populate_timestamp`]: the high/low
    /// 24-bit split of the previous timestamp, the `compare_low` selector (whether
    /// the high limbs match), and the `(diff − 1)` limbs of the access-time gap
    /// (with their range checks).
    pub fn witgen<WB: crate::air::WitnessBuilder>(
        wb: &mut WB,
        cols: &mut MemoryAccessTimestamp<WB::Field>,
        prev_timestamp: WB::Nat,
        current_timestamp: WB::Nat,
    ) {
        let prev_high = wb.bits(prev_timestamp, 24, 32);
        let prev_low = wb.bits(prev_timestamp, 0, 24);
        let current_high = wb.bits(current_timestamp, 24, 32);
        let current_low = wb.bits(current_timestamp, 0, 24);
        cols.prev_high = wb.nat_to_field(prev_high);
        cols.prev_low = wb.nat_to_field(prev_low);

        let use_low = wb.eq(prev_high, current_high);
        cols.compare_low = wb.nat_to_field(use_low);
        let prev_tv = wb.select(use_low, prev_low, prev_high);
        let cur_tv = wb.select(use_low, current_low, current_high);

        let one = wb.const_nat(1);
        let cm = wb.wrapping_sub(cur_tv, prev_tv);
        let diff_minus_one = wb.wrapping_sub(cm, one);
        let diff_low_limb = wb.bits(diff_minus_one, 0, 16);
        cols.diff_low_limb = wb.nat_to_field(diff_low_limb);
        let diff_high_limb = wb.bits(diff_minus_one, 16, 8);
        cols.diff_high_limb = wb.nat_to_field(diff_high_limb);

        let zero = wb.const_nat(0);
        wb.add_bit_range_check(diff_low_limb, 16);
        wb.add_u8_range_check(diff_high_limb, zero);
    }
}

impl<F: PrimeField32> MemoryAccessTimestamp<F> {
    pub fn populate_timestamp(
        &mut self,
        prev_timestamp: u64,
        current_timestamp: u64,
        output: &mut impl ByteRecord,
    ) {
        assert!(
            prev_timestamp < current_timestamp,
            "prev_timestamp: {prev_timestamp}, current_timestamp: {current_timestamp}"
        );
        let prev_high = (prev_timestamp >> 24) as u32;
        let prev_low = (prev_timestamp & 0xFFFFFF) as u32;
        let current_high = (current_timestamp >> 24) as u32;
        let current_low = (current_timestamp & 0xFFFFFF) as u32;
        self.prev_high = F::from_canonical_u32(prev_high);
        self.prev_low = F::from_canonical_u32(prev_low);

        // Fill columns used for verifying memory access time is increasing.
        let use_low_comparison = prev_high == current_high;
        self.compare_low = F::from_bool(use_low_comparison);
        let prev_time_value = if use_low_comparison { prev_low } else { prev_high };
        let current_time_value = if use_low_comparison { current_low } else { current_high };

        let diff_minus_one = current_time_value - prev_time_value - 1;
        let diff_low_limb = (diff_minus_one & 0xFFFF) as u16;
        self.diff_low_limb = F::from_canonical_u16(diff_low_limb);
        let diff_high_limb = (diff_minus_one >> 16) as u8;
        self.diff_high_limb = F::from_canonical_u8(diff_high_limb);

        // Add a byte table lookup with the u16 range check.
        output.add_bit_range_check(diff_low_limb, 16);
        output.add_u8_range_check(diff_high_limb, 0);
    }
}

// Witgen in an unconstrained `impl<T>` (column type is the builder's `Field`).
impl<T> RegisterAccessTimestamp<T> {
    /// Backend-agnostic witgen: `prev_low` (old timestamp, selected on whether the
    /// high limbs match) and `diff_low_limb` (low limb of the access-time diff),
    /// plus the diff range checks.
    pub fn witgen<WB: crate::air::WitnessBuilder>(
        wb: &mut WB,
        cols: &mut RegisterAccessTimestamp<WB::Field>,
        prev_timestamp: WB::Nat,
        current_timestamp: WB::Nat,
    ) {
        let prev_high = wb.bits(prev_timestamp, 24, 32);
        let prev_low = wb.bits(prev_timestamp, 0, 24);
        let current_high = wb.bits(current_timestamp, 24, 32);
        let current_low = wb.bits(current_timestamp, 0, 24);

        let high_eq = wb.eq(prev_high, current_high);
        let zero = wb.const_nat(0);
        let old_timestamp = wb.select(high_eq, prev_low, zero);
        cols.prev_low = wb.nat_to_field(old_timestamp);

        let one = wb.const_nat(1);
        let cm = wb.wrapping_sub(current_low, old_timestamp);
        let diff_minus_one = wb.wrapping_sub(cm, one);
        let diff_low_limb = wb.bits(diff_minus_one, 0, 16);
        cols.diff_low_limb = wb.nat_to_field(diff_low_limb);

        // Byte-table lookups (skipped by the columns-only interpreter).
        wb.add_bit_range_check(diff_low_limb, 16);
        let diff_high_limb = wb.bits(diff_minus_one, 16, 8);
        wb.add_u8_range_check(diff_high_limb, zero);
    }
}

impl<F: PrimeField32> RegisterAccessTimestamp<F> {
    pub fn populate_timestamp(
        &mut self,
        prev_timestamp: u64,
        current_timestamp: u64,
        output: &mut impl ByteRecord,
    ) {
        let mut wb = crate::air::HostWitnessBuilder::<F, _>::new(output);
        Self::witgen(&mut wb, self, prev_timestamp, current_timestamp);
    }
}
