use crate::cpu::{MemoryReadRecord, MemoryRecord, MemoryRecordEnum, MemoryWriteRecord};
use crate::field::event::FieldEvent;
use p3_field::Field;

use super::{MemoryAccessCols, MemoryReadCols, MemoryReadWriteCols, MemoryWriteCols};

impl<F: Field> MemoryWriteCols<F> {
    pub fn populate(&mut self, record: MemoryWriteRecord, new_field_events: &mut Vec<FieldEvent>) {
        let current_record = MemoryRecord {
            value: record.value,
            segment: record.segment,
            timestamp: record.timestamp,
        };
        let prev_record = MemoryRecord {
            value: record.prev_value,
            segment: record.prev_segment,
            timestamp: record.prev_timestamp,
        };
        self.prev_value = prev_record.value.into();
        self.access
            .populate_access(current_record, prev_record, new_field_events);
    }
}

impl<F: Field> MemoryReadCols<F> {
    pub fn populate(&mut self, record: MemoryReadRecord, new_field_events: &mut Vec<FieldEvent>) {
        let current_record = MemoryRecord {
            value: record.value,
            segment: record.segment,
            timestamp: record.timestamp,
        };
        let prev_record = MemoryRecord {
            value: record.value,
            segment: record.prev_segment,
            timestamp: record.prev_timestamp,
        };
        self.access
            .populate_access(current_record, prev_record, new_field_events);
    }
}

impl<F: Field> MemoryReadWriteCols<F> {
    pub fn populate(&mut self, record: MemoryRecordEnum, new_field_events: &mut Vec<FieldEvent>) {
        match record {
            MemoryRecordEnum::Read(read_record) => {
                self.populate_read(read_record, new_field_events);
            }
            MemoryRecordEnum::Write(write_record) => {
                self.populate_write(write_record, new_field_events);
            }
        }
    }

    pub fn populate_write(
        &mut self,
        record: MemoryWriteRecord,
        new_field_events: &mut Vec<FieldEvent>,
    ) {
        let current_record = MemoryRecord {
            value: record.value,
            segment: record.segment,
            timestamp: record.timestamp,
        };
        let prev_record = MemoryRecord {
            value: record.prev_value,
            segment: record.prev_segment,
            timestamp: record.prev_timestamp,
        };
        self.prev_value = prev_record.value.into();
        self.access
            .populate_access(current_record, prev_record, new_field_events);
    }

    pub fn populate_read(
        &mut self,
        record: MemoryReadRecord,
        new_field_events: &mut Vec<FieldEvent>,
    ) {
        let current_record = MemoryRecord {
            value: record.value,
            segment: record.segment,
            timestamp: record.timestamp,
        };
        let prev_record = MemoryRecord {
            value: record.value,
            segment: record.prev_segment,
            timestamp: record.prev_timestamp,
        };
        self.prev_value = prev_record.value.into();
        self.access
            .populate_access(current_record, prev_record, new_field_events);
    }
}

impl<F: Field> MemoryAccessCols<F> {
    pub(crate) fn populate_access(
        &mut self,
        current_record: MemoryRecord,
        prev_record: MemoryRecord,
        new_field_events: &mut Vec<FieldEvent>,
    ) {
        self.value = current_record.value.into();

        self.prev_segment = F::from_canonical_u32(prev_record.segment);
        self.prev_clk = F::from_canonical_u32(prev_record.timestamp);

        // Fill columns used for verifying current memory access time value is greater than previous's.
        let use_clk_comparison = prev_record.segment == current_record.segment;
        self.use_clk_comparison = F::from_bool(use_clk_comparison);
        let prev_time_value = if use_clk_comparison {
            prev_record.timestamp
        } else {
            prev_record.segment
        };
        self.prev_time_value = F::from_canonical_u32(prev_time_value);
        let current_time_value = if use_clk_comparison {
            current_record.timestamp
        } else {
            current_record.segment
        };
        self.current_time_value = F::from_canonical_u32(current_time_value);

        // Add a field op event for the prev_time_value < current_time_value constraint.
        let field_event = FieldEvent::new(true, prev_time_value, current_time_value);
        new_field_events.push(field_event);
    }
}
